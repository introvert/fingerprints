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

func TestParseSYNIPv6ExtHeader(t *testing.T) {
	ip6 := make([]byte, 40)
	ip6[0] = 0x60
	ip6[4], ip6[5] = 0, 8+32 // payload: 8 (dest opts) + 32 (tcp)
	ip6[6] = 60              // next: destination options
	ip6[7] = 57              // hop limit
	copy(ip6[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	dest := []byte{6, 0, 1, 4, 0, 0, 0, 0} // next=TCP, len=0 (8 bytes), PadN
	tcp := []byte{0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x80, 0x02, 0xfd, 0x20, 0, 0, 0, 0,
		2, 4, 0x05, 0xa0, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}[:32]
	tcp[12] = 0x80 // 32-byte header
	s, key := parseSYN(append(append(ip6, dest...), tcp...), map[int]bool{443: true})
	if s == nil {
		t.Fatal("not parsed")
	}
	if key != "[2001:db8::1]:50000" || s.IPVersion != 6 || s.MSS != 1440 || len(s.IPv6ExtHeaders) != 1 || s.InitialTTL != 64 {
		t.Errorf("key=%s %+v", key, s)
	}
}
