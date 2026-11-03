package h2fp

import "testing"

func FuzzTracker(f *testing.F) {
	f.Add([]byte(preface + "\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x10\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		tr := NewTracker()
		tr.Write([]byte(preface))
		tr.Write(b)
		tr.Fingerprint()
		scanHPACK(b)
	})
}
