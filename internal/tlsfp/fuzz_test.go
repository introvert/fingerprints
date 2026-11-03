package tlsfp

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		if ch, err := Parse(b); err == nil {
			ch.Fingerprint(false)
		}
		if ch, err := ParseHandshake(b); err == nil {
			ch.Fingerprint(true)
		}
	})
}
