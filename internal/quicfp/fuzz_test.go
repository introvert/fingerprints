package quicfp

import "testing"

func FuzzObserve(f *testing.F) {
	f.Add([]byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x41, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		NewTable().Observe("1.2.3.4:5", b)
	})
}
