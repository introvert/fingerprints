package quicfp

import (
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 9001 Appendix A.5: ChaCha20-Poly1305 short header packet and key update.
func TestRFC9001ChaChaShortHeader(t *testing.T) {
	secret := unhex(t, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
	a := newAppState(secret)
	a.largestPN = 654360563
	pt, ok := a.decrypt(unhex(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"), 0)
	if !ok || hex.EncodeToString(pt) != "01" {
		t.Fatalf("decrypt: ok=%v pt=%x", ok, pt)
	}
	if a.keys.name != "TLS_CHACHA20_POLY1305_SHA256" || a.largestPN != 654360564 {
		t.Errorf("suite=%s pn=%d", a.keys.name, a.largestPN)
	}
	if ku := hex.EncodeToString(a.keys.next().secret); ku != "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9" {
		t.Errorf("key update secret = %s", ku)
	}
}

func TestDecodePN(t *testing.T) {
	// RFC 9000 A.3 example
	if pn := decodePN(0xa82f30ea, 0x9b32, 2); pn != 0xa82f9b32 {
		t.Errorf("pn = %x", pn)
	}
}
