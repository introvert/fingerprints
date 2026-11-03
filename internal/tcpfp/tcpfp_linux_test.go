//go:build linux

package tcpfp

import "testing"

func TestParseSYN(t *testing.T) {
	// IPv4 + TCP SYN from a Windows-like stack: TTL 117, MSS 1460, NOP, WS 8, NOP, NOP, SACK_PERM
	pkt := []byte{
		0x45, 0, 0, 52, 0x12, 0x34, 0x40, 0, 117, 6, 0, 0, 203, 0, 113, 7, 10, 0, 0, 1,
		0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x80, 0x02, 0xfa, 0xf0, 0, 0, 0, 0,
		2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2,
	}
	s, key := parseSYN(pkt, map[int]bool{443: true})
	if s == nil {
		t.Fatal("not parsed")
	}
	if key != "203.0.113.7:50000" {
		t.Errorf("key = %s", key)
	}
	if s.JA4T != "64240_2-1-3-1-1-4_1460_8" {
		t.Errorf("ja4t = %s", s.JA4T)
	}
	if s.InitialTTL != 128 || s.Hops != 11 || s.OSGuess != "Windows" || s.MTUGuess != 1500 {
		t.Errorf("ttl=%d hops=%d os=%s mtu=%d", s.InitialTTL, s.Hops, s.OSGuess, s.MTUGuess)
	}
	if _, k := parseSYN(pkt, map[int]bool{80: true}); k != "" {
		t.Error("port filter ignored")
	}
}
