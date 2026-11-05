package echcfg

import (
	"crypto/tls"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestECHRoundTrip: a Go client using our ECHConfigList is accepted and the
// server sees the inner server name.
func TestECHRoundTrip(t *testing.T) {
	k, err := LoadOrCreate(filepath.Join(t.TempDir(), "ech.json"), "public.example")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := k.TLSKey()
	if err != nil {
		t.Fatal(err)
	}
	list, _ := k.ConfigList()
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	ts.Close()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	var inner string
	done := make(chan tls.ConnectionState, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{tk},
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { inner = chi.ServerName; return nil, nil }})
		s.SetDeadline(time.Now().Add(3 * time.Second))
		s.Handshake()
		done <- s.ConnectionState()
		s.Close()
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "secret.example", InsecureSkipVerify: true, EncryptedClientHelloConfigList: list})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	st := <-done
	if !st.ECHAccepted || inner != "secret.example" || st.ServerName != "secret.example" {
		t.Fatalf("ECH accepted=%v inner=%q sni=%q", st.ECHAccepted, inner, st.ServerName)
	}
}
