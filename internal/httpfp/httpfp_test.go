package httpfp

import (
	"strings"
	"testing"
)

func TestTrackerOrderAndBodies(t *testing.T) {
	tr := NewTracker()
	stream := "POST /api HTTP/1.1\r\nHost: a\r\nContent-Length: 30\r\nX-B: 1\r\nx-a: 2\r\n\r\n" +
		`{"k":"v","n":"GET / HTTP/1.1"}` +
		"GET /next?q=1 HTTP/1.1\r\nHost: a\r\nUser-Agent: t\r\nCookie: z=1; a=2\r\n\r\n"
	for i := 0; i < len(stream); i += 5 {
		tr.Write([]byte(stream[i:min(i+5, len(stream))]))
	}
	r := tr.Request("POST", "/api")
	if r == nil || len(r.Headers) != 4 || r.Headers[3].Name != "x-a" {
		t.Fatalf("first request: %+v", r)
	}
	r2 := tr.Request("GET", "/next?q=1")
	if r2 == nil || r2.Headers[2].Name != "Cookie" {
		t.Fatalf("second request: %+v", r2)
	}
}

func TestJA4H(t *testing.T) {
	h := []Header{
		{Name: "Host", Value: "x"}, {Name: "User-Agent", Value: "u"}, {Name: "Accept", Value: "*/*"}, {Name: "Accept-Language", Value: "en-US,en;q=0.9"},
		{Name: "Cookie", Value: "b=2; a=1"}, {Name: "Referer", Value: "https://r/"},
	}
	ja4h, raw := JA4H("GET", "11", h)
	if !strings.HasPrefix(ja4h, "ge11cr04enus_") {
		t.Errorf("ja4h = %s", ja4h)
	}
	if raw != "ge11cr04enus_Host,User-Agent,Accept,Accept-Language_a,b_a=1,b=2" {
		t.Errorf("raw = %s", raw)
	}
	if parts := strings.Split(ja4h, "_"); len(parts) != 4 || len(parts[1]) != 12 {
		t.Errorf("bad shape %s", ja4h)
	}
	none, _ := JA4H("POST", "20", []Header{{Name: ":method", Value: "POST"}, {Name: "accept", Value: "*/*"}})
	if !strings.HasPrefix(none, "po20nn010000_") || !strings.HasSuffix(none, "_000000000000_000000000000") {
		t.Errorf("no cookie ja4h = %s", none)
	}
}
