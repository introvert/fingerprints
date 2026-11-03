//go:build linux

package tcpfp

import "testing"

func FuzzParseSYN(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 1, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 2, 0xff, 0xff, 0, 0, 0, 0, 2, 4, 5, 0xb4})
	f.Fuzz(func(t *testing.T, b []byte) { parseSYN(b, map[int]bool{443: true}) })
}
