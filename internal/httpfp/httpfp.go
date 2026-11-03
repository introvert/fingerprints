// Package httpfp captures HTTP/1.x request headers in wire order (Go's
// net/http discards ordering and casing) and computes JA4H.
package httpfp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Header is a raw header line in wire order with original casing.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Encoding optionally describes the wire encoding (HPACK representation for HTTP/2).
	Encoding any `json:"hpack,omitempty"`
}

// Request is one raw HTTP/1.x request head.
type Request struct {
	RequestLine string   `json:"request_line"`
	Method      string   `json:"method"`
	Target      string   `json:"target"`
	Version     string   `json:"version"`
	Headers     []Header `json:"headers"`
	LineEnding  string   `json:"line_ending"`
	HeadBytes   int      `json:"head_bytes"`
	used        bool
}

var requestLine = regexp.MustCompile(`(?:^|[^A-Z])([A-Z]{3,10}) (\S+) (HTTP/1\.[01])\r?\n`)

// Tracker records request heads seen on one HTTP/1.x connection.
type Tracker struct {
	mu   sync.Mutex
	buf  []byte
	reqs []*Request
}

// NewTracker returns an empty tracker.
func NewTracker() *Tracker { return &Tracker{} }

// Write feeds client->server bytes. It never fails.
func (t *Tracker) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	for {
		end := bytes.Index(t.buf, []byte("\r\n\r\n"))
		sepLen := 4
		if alt := bytes.Index(t.buf, []byte("\n\n")); alt >= 0 && (end < 0 || alt < end) {
			end, sepLen = alt, 2
		}
		if end < 0 {
			break
		}
		block := t.buf[:end+sepLen]
		t.buf = t.buf[end+sepLen:]
		// The block may be prefixed by a request body; locate the last
		// request line inside it.
		locs := requestLine.FindAllSubmatchIndex(block, -1)
		if len(locs) == 0 {
			continue
		}
		start := locs[len(locs)-1][2]
		if r := parseHead(block[start:]); r != nil {
			t.reqs = append(t.reqs, r)
			if len(t.reqs) > 64 {
				t.reqs = t.reqs[len(t.reqs)-64:]
			}
		}
	}
	if len(t.buf) > 64<<10 { // body bytes; keep only a tail
		t.buf = append([]byte(nil), t.buf[len(t.buf)-8<<10:]...)
	}
	return len(p), nil
}

func parseHead(b []byte) *Request {
	s := string(b)
	le := "\r\n"
	if !strings.Contains(s, "\r\n") {
		le = "\n"
	}
	lines := strings.Split(strings.TrimRight(s, "\r\n"), le)
	if len(lines) == 0 {
		return nil
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) != 3 {
		return nil
	}
	r := &Request{RequestLine: lines[0], Method: parts[0], Target: parts[1], Version: parts[2], LineEnding: fmt.Sprintf("%q", le), HeadBytes: len(b)}
	for _, l := range lines[1:] {
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		r.Headers = append(r.Headers, Header{Name: l[:i], Value: strings.TrimSpace(l[i+1:])})
	}
	return r
}

// Request returns the oldest unclaimed request matching method and target.
func (t *Tracker) Request(method, target string) *Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range t.reqs {
		if !r.used && r.Method == method && r.Target == target {
			r.used = true
			return r
		}
	}
	return nil
}

// JA4H computes the JA4H HTTP client fingerprint from an ordered header list.
// version is "10", "11", "20" or "30". Pseudo headers (":method" ...) are ignored.
func JA4H(method, version string, headers []Header) (ja4h, raw string) {
	m := strings.ToLower(method)
	if len(m) > 2 {
		m = m[:2]
	}
	var names []string
	var cookies []string
	hasCookie, hasReferer := "n", "n"
	lang := "0000"
	for _, h := range headers {
		ln := strings.ToLower(h.Name)
		switch {
		case strings.HasPrefix(h.Name, ":"):
			continue
		case ln == "cookie":
			hasCookie = "c"
			for _, c := range strings.Split(h.Value, ";") {
				if c = strings.TrimSpace(c); c != "" {
					cookies = append(cookies, c)
				}
			}
			continue
		case ln == "referer":
			hasReferer = "r"
			continue
		case ln == "accept-language":
			l := strings.ToLower(strings.ReplaceAll(strings.Split(h.Value, ",")[0], "-", ""))
			l = strings.Split(l, ";")[0]
			if len(l) > 4 {
				l = l[:4]
			}
			lang = l + strings.Repeat("0", 4-len(l))
		}
		names = append(names, h.Name)
	}
	a := fmt.Sprintf("%s%s%s%s%02d%s", m, version, hasCookie, hasReferer, min(len(names), 99), lang)
	b := strings.Join(names, ",")
	sort.Strings(cookies)
	var cnames []string
	for _, c := range cookies {
		cnames = append(cnames, strings.SplitN(c, "=", 2)[0])
	}
	sort.Strings(cnames)
	c := strings.Join(cnames, ",")
	d := strings.Join(cookies, ",")
	h := func(s string) string {
		if s == "" {
			return "000000000000"
		}
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])[:12]
	}
	return a + "_" + h(b) + "_" + h(c) + "_" + h(d), a + "_" + b + "_" + c + "_" + d
}
