package server

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/http3"

	"github.com/introvert/fingerprints/internal/capture"
)

func TestHTTP3Fingerprint(t *testing.T) {
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	ts.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	srv := &capture.Server{Handler: New(Config{}, nil), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go srv.ServeH3(pc)

	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.Close()
	c := &http.Client{Transport: tr}
	resp, err := c.Get("https://" + pc.LocalAddr().String() + "/api/server")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var rep struct {
		Network struct{ Protocol string } `json:"network"`
		TLS     struct{ JA4 string }      `json:"tls"`
		HTTP3   struct {
			QUIC struct {
				Version         string `json:"version"`
				InitialPackets  int    `json:"initial_packets"`
				QUICFingerprint string `json:"quic_fingerprint"`
				TLS             struct {
					JA4         string `json:"ja4"`
					ClientHello struct {
						QUICParams []any `json:"quic_transport_parameters"`
					} `json:"client_hello"`
				} `json:"tls"`
			} `json:"quic"`
		} `json:"http3"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if rep.Network.Protocol != "h3" {
		t.Errorf("protocol = %q", rep.Network.Protocol)
	}
	q := rep.HTTP3.QUIC
	if q.Version != "v1" || q.InitialPackets == 0 || !strings.HasPrefix(q.TLS.JA4, "q13") {
		t.Errorf("quic fingerprint = %+v", q)
	}
	if len(q.TLS.ClientHello.QUICParams) == 0 || q.QUICFingerprint == "" {
		t.Errorf("no transport parameters: %s", b)
	}
	var full map[string]any
	json.Unmarshal(b, &full)
	httpInfo := full["http"].(map[string]any)
	if src := httpInfo["header_source"]; src != "qpack (wire order, decrypted from 1-RTT packets)" {
		t.Errorf("header_source = %v", src)
	}
	// quic-go's client sends pseudo headers alphabetically (:authority first)
	if order := httpInfo["header_order"].([]any); len(order) < 4 || order[0] != ":authority" || order[1] != ":method" {
		t.Errorf("header order = %v", order)
	}
	if httpInfo["qpack_codes"] == "" || httpInfo["ja4h"] == "" {
		t.Errorf("qpack_codes=%v ja4h=%v", httpInfo["qpack_codes"], httpInfo["ja4h"])
	}
	h3 := full["http3"].(map[string]any)
	ctl, _ := h3["control"].(map[string]any)
	if ctl == nil || len(ctl["settings"].([]any)) == 0 || h3["h3_fingerprint"] == "" {
		t.Errorf("no decrypted control stream: %v", h3)
	} else {
		t.Logf("h3_fingerprint=%v cipher=%v uni=%v", h3["h3_fingerprint"], ctl["decrypted_with"], ctl["uni_stream_types"])
	}
	if rep.TLS.JA4 != q.TLS.JA4 {
		t.Errorf("tls.ja4 %q != quic ja4 %q", rep.TLS.JA4, q.TLS.JA4)
	}
}
