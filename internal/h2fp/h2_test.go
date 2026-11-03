package h2fp

import (
	"bytes"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestAkamaiFingerprint(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(preface)
	fr := http2.NewFramer(&buf, nil)
	fr.WriteSettings(
		http2.Setting{ID: 1, Val: 65536}, http2.Setting{ID: 2, Val: 0},
		http2.Setting{ID: 4, Val: 6291456}, http2.Setting{ID: 6, Val: 262144},
	)
	fr.WriteWindowUpdate(0, 15663105)
	enc := func(fields ...string) []byte {
		var hb bytes.Buffer
		e := hpack.NewEncoder(&hb)
		for i := 0; i < len(fields); i += 2 {
			e.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
		}
		return hb.Bytes()
	}
	fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, EndHeaders: true, EndStream: true,
		BlockFragment: enc(":method", "GET", ":authority", "a.test", ":scheme", "https", ":path", "/x", "user-agent", "ua", "accept", "*/*"),
		Priority:      http2.PriorityParam{Weight: 255, Exclusive: true},
	})
	fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 3, EndHeaders: true,
		BlockFragment: enc(":method", "POST", ":authority", "a.test", ":scheme", "https", ":path", "/y", "content-type", "x"),
	})

	tr := NewTracker()
	data := buf.Bytes()
	// feed in small chunks to exercise reassembly
	for i := 0; i < len(data); i += 7 {
		tr.Write(data[i:min(i+7, len(data))])
	}
	f := tr.Fingerprint()
	if f == nil {
		t.Fatal("no fingerprint")
	}
	want := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if f.Akamai != want {
		t.Errorf("akamai = %q, want %q", f.Akamai, want)
	}
	if f.FirstHeaders.Priority == nil || f.FirstHeaders.Priority.Weight != 256 || !f.FirstHeaders.Priority.Exclusive {
		t.Errorf("priority = %+v", f.FirstHeaders.Priority)
	}
	hb := tr.RequestHeaders("POST", "/y")
	if hb == nil || hb.Headers[4].Name != "content-type" {
		t.Fatalf("second request headers: %+v", hb)
	}
	if tr.RequestHeaders("POST", "/y") != nil {
		t.Error("header block returned twice")
	}
}
