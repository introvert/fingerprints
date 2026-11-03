package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/introvert/fingerprints/internal/capture"
	"github.com/introvert/fingerprints/internal/store"
)

func startServer(t *testing.T) (string, *http.Client) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "fp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// borrow httptest's self-signed certificate
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	ts.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &capture.Server{Handler: New(Config{}, st), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}}
	go srv.ServeTLS(ln)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	return "https://" + ln.Addr().String(), &http.Client{Transport: tr}
}

func getJSON(t *testing.T, c *http.Client, req *http.Request, wantStatus int) map[string]any {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL, resp.StatusCode, wantStatus, b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode: %v: %s", err, b)
	}
	return m
}

func TestEndToEnd(t *testing.T) {
	base, c := startServer(t)

	// echo mode, server side only
	req, _ := http.NewRequest("GET", base+"/api/server", nil)
	req.Header.Set("User-Agent", "fp-test/1.0")
	rep := getJSON(t, c, req, 200)
	tlsInfo := rep["tls"].(map[string]any)
	if !strings.HasPrefix(tlsInfo["ja4"].(string), "t13i") {
		t.Errorf("ja4 = %v", tlsInfo["ja4"])
	}
	h2 := rep["http2"].(map[string]any)
	if h2["akamai_fingerprint"] == "" {
		t.Error("no akamai fingerprint")
	}
	httpInfo := rep["http"].(map[string]any)
	if httpInfo["header_source"] != "hpack (wire order)" {
		t.Errorf("header_source = %v", httpInfo["header_source"])
	}

	// store mode with client payload
	payload := `{"label":"t1","client":{"components":{"navigator":{"value":{"userAgent":"fp-test/1.0","languages":["en-US"]}},"timing":{"value":{"x":1}}}},"libraries":{"fingerprintjs":{"visitorId":"abc"}}}`
	req, _ = http.NewRequest("POST", base+"/api/fingerprint?mode=store", bytes.NewBufferString(payload))
	req.Header.Set("User-Agent", "fp-test/1.0")
	stored := getJSON(t, c, req, 201)
	id, _ := stored["id"].(string)
	if id == "" || !strings.HasSuffix(stored["permalink"].(string), "/f/"+id) {
		t.Fatalf("store response: id=%v permalink=%v", stored["id"], stored["permalink"])
	}
	sum := stored["summary"].(map[string]any)
	if sum["fingerprintjs_visitor_id"] != "abc" || sum["browser_hash"] == nil {
		t.Errorf("summary = %v", sum)
	}

	// read back by id
	req, _ = http.NewRequest("GET", base+"/api/fingerprints/"+id, nil)
	got := getJSON(t, c, req, 200)
	if got["id"] != id || got["label"] != "t1" {
		t.Errorf("read back: id=%v label=%v", got["id"], got["label"])
	}
	// the stable browser hash ignores volatile components
	payload2 := strings.Replace(payload, `"x":1`, `"x":2`, 1)
	req, _ = http.NewRequest("POST", base+"/api/fingerprint", bytes.NewBufferString(payload2))
	req.Header.Set("User-Agent", "fp-test/1.0")
	echo := getJSON(t, c, req, 200)
	if echo["hashes"].(map[string]any)["browser"] != stored["hashes"].(map[string]any)["browser"] {
		t.Error("browser hash changed when only a volatile component changed")
	}
	if echo["id"] != nil {
		t.Error("echo mode must not store")
	}

	// history listing and compare
	req, _ = http.NewRequest("GET", base+"/api/fingerprints?visitor_id=abc", nil)
	list := getJSON(t, c, req, 200)
	if list["count"].(float64) != 1 {
		t.Errorf("list = %v", list)
	}
	req, _ = http.NewRequest("GET", base+"/api/compare?a="+id+"&b="+id, nil)
	cmp := getJSON(t, c, req, 200)
	if cmp["different_fields"].(float64) != 0 {
		t.Errorf("self compare differs: %v", cmp["differences"])
	}
	req, _ = http.NewRequest("GET", base+"/api/fingerprints/doesnotexist", nil)
	getJSON(t, c, req, 404)

	// text format
	resp, err := c.Get(base + "/api/server?format=text")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "tls.ja4 = ") {
		t.Errorf("text format missing tls.ja4:\n%s", b)
	}
}

func TestHTTP1HeaderOrder(t *testing.T) {
	base, _ := startServer(t)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}}
	req, _ := http.NewRequest("GET", base+"/api/server", nil)
	req.Header.Set("X-Zeta", "1")
	rep := getJSON(t, c, req, 200)
	h := rep["http"].(map[string]any)
	if h["header_source"] != "raw request (wire order)" {
		t.Fatalf("header_source = %v", h["header_source"])
	}
	order := h["header_order"].([]any)
	if order[0] != "Host" {
		t.Errorf("order = %v", order)
	}
	if rep["network"].(map[string]any)["protocol"] != "http/1.1" {
		t.Errorf("protocol = %v", rep["network"])
	}
}
