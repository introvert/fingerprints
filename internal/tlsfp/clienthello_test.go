package tlsfp

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// buildHello assembles a ClientHello record from parts.
func buildHello(ciphers []uint16, exts [][2]any) []byte {
	u16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // session id
	body = append(body, u16(len(ciphers)*2)...)
	for _, c := range ciphers {
		body = append(body, u16(int(c))...)
	}
	body = append(body, 1, 0) // compression: null
	var eb []byte
	for _, e := range exts {
		data := e[1].([]byte)
		eb = append(eb, u16(int(e[0].(uint16)))...)
		eb = append(eb, u16(len(data))...)
		eb = append(eb, data...)
	}
	body = append(body, u16(len(eb))...)
	body = append(body, eb...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func vec16(vs ...uint16) []byte {
	out := []byte{byte(len(vs) * 2 >> 8), byte(len(vs) * 2)}
	for _, v := range vs {
		out = append(out, byte(v>>8), byte(v))
	}
	return out
}

// TestJA4SpecExample reproduces the example from the JA4 specification:
// JA4 = t13d1516h2_8daaf6152771_e5627efa2ab1
func TestJA4SpecExample(t *testing.T) {
	ciphers := []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	sni := []byte{0, 14, 0, 0, 11}
	sni = append(sni, "example.com"...)
	alpn := []byte{0, 12, 2, 'h', '2', 8}
	alpn = append(alpn, "http/1.1"...)
	sv := []byte{6, 0x2a, 0x2a, 0x03, 0x04, 0x03, 0x03}
	exts := [][2]any{
		{uint16(0x1a1a), []byte{}},
		{uint16(0x0000), sni},
		{uint16(0x0017), []byte{}},
		{uint16(0xff01), []byte{0}},
		{uint16(0x000a), vec16(0x2a2a, 0x001d, 0x0017, 0x0018)},
		{uint16(0x000b), []byte{1, 0}},
		{uint16(0x0023), []byte{}},
		{uint16(0x0010), alpn},
		{uint16(0x0005), []byte{1, 0, 0, 0, 0}},
		{uint16(0x000d), vec16(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)},
		{uint16(0x0012), []byte{}},
		{uint16(0x0033), []byte{0, 0}},
		{uint16(0x002d), []byte{1, 1}},
		{uint16(0x002b), sv},
		{uint16(0x001b), []byte{2, 0, 2}},
		{uint16(0x4469), []byte{0, 3, 2, 'h', '2'}},
		{uint16(0x0015), []byte{0, 0, 0}},
	}
	raw := buildHello(ciphers, exts)
	ch, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := ch.Fingerprint(false)
	if want := "t13d1516h2_8daaf6152771_e5627efa2ab1"; f.JA4 != want {
		t.Errorf("JA4 = %s, want %s\nraw: %s", f.JA4, want, f.JA4R)
	}
	if ch.ServerName != "example.com" || ch.ALPN[0] != "h2" || len(ch.ALPS) != 1 {
		t.Errorf("decoded fields wrong: sni=%q alpn=%v alps=%v", ch.ServerName, ch.ALPN, ch.ALPS)
	}
	if strings.Contains(f.JA3, "2570") || strings.Contains(f.JA3, "6682") || strings.Contains(f.JA3, "10794") {
		t.Errorf("GREASE leaked into JA3: %s", f.JA3)
	}
	if !f.ClientHello.GREASE {
		t.Error("GREASE not detected")
	}
	// Incomplete input must report ErrIncomplete.
	if _, err := Parse(raw[:len(raw)-10]); err != ErrIncomplete {
		t.Errorf("truncated: err = %v, want ErrIncomplete", err)
	}
}

type recConn struct {
	net.Conn
	buf []byte
}

func (c *recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.buf = append(c.buf, p[:n]...)
	return n, err
}

// TestGoClientHello parses a real ClientHello produced by crypto/tls.
func TestGoClientHello(t *testing.T) {
	cli, srv := net.Pipe()
	rc := &recConn{Conn: srv}
	go func() {
		c := tls.Client(cli, &tls.Config{ServerName: "fp.test", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Handshake()
		cli.Close()
	}()
	b := make([]byte, 4096)
	srv.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, err := rc.Read(b); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(rc.buf); err != ErrIncomplete {
			break
		}
	}
	srv.Close()
	ch, err := Parse(rc.buf)
	if err != nil {
		t.Fatal(err)
	}
	f := ch.Fingerprint(false)
	if !strings.HasPrefix(f.JA4, "t13d") || !strings.Contains(f.JA4, "h2_") {
		t.Errorf("unexpected JA4 %s", f.JA4)
	}
	if ch.ServerName != "fp.test" {
		t.Errorf("SNI = %q", ch.ServerName)
	}
	if len(f.JA3Hash) != 32 || len(f.PeetHash) != 32 {
		t.Errorf("bad hashes %s %s", f.JA3Hash, f.PeetHash)
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !IsGREASE(v) {
			t.Errorf("%04x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x0a1a, 0x1301, 0x0000} {
		if IsGREASE(v) {
			t.Errorf("%04x should not be GREASE", v)
		}
	}
}

func TestComplete(t *testing.T) {
	raw := buildHello([]uint16{0x1301}, [][2]any{{uint16(0x002b), []byte{2, 3, 4}}})
	for i := 0; i < len(raw); i++ {
		if Complete(raw[:i]) {
			t.Fatalf("complete at %d of %d", i, len(raw))
		}
	}
	if !Complete(raw) {
		t.Fatal("full hello not complete")
	}
}
