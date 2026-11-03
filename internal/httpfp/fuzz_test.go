package httpfp

import "testing"

func FuzzTracker(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		tr := NewTracker()
		tr.Write(b)
		tr.Request("GET", "/")
		JA4H("GET", "11", []Header{{Name: "Cookie", Value: string(b)}, {Name: "Accept-Language", Value: string(b)}})
	})
}
