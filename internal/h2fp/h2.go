// Package h2fp passively observes the decrypted HTTP/2 byte stream a client
// sends and derives the HTTP/2 fingerprint (Akamai format) plus per-request
// header order (decoded with HPACK).
package h2fp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2/hpack"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Frame types.
const (
	frameData         = 0x0
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePushPromise  = 0x5
	framePing         = 0x6
	frameGoAway       = 0x7
	frameWindowUpdate = 0x8
	frameContinuation = 0x9
)

var settingNames = map[uint16]string{
	1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE",
	5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE", 8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES",
}

var frameNames = map[byte]string{
	0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE",
	6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION",
}

// Setting is a single SETTINGS parameter.
type Setting struct {
	ID    uint16 `json:"id"`
	Name  string `json:"name"`
	Value uint32 `json:"value"`
}

// Priority describes a PRIORITY frame or HEADERS priority block.
type Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    int    `json:"weight"`
}

// Header is a decoded header field, in wire order.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HeaderBlock is a decoded request header block.
type HeaderBlock struct {
	StreamID uint32    `json:"stream_id"`
	Flags    []string  `json:"flags,omitempty"`
	Priority *Priority `json:"priority,omitempty"`
	Headers  []Header  `json:"headers"`
	method   string
	path     string
	used     bool
}

// FrameSummary is a compact log entry of frames seen at connection start.
type FrameSummary struct {
	Type     string `json:"type"`
	StreamID uint32 `json:"stream_id"`
	Length   int    `json:"length"`
	Flags    byte   `json:"flags"`
}

// Fingerprint is the HTTP/2 connection fingerprint.
type Fingerprint struct {
	Akamai          string         `json:"akamai_fingerprint"`
	AkamaiHash      string         `json:"akamai_fingerprint_hash"`
	Settings        []Setting      `json:"settings"`
	WindowUpdate    uint32         `json:"connection_window_update"`
	PriorityFrames  []Priority     `json:"priority_frames"`
	PseudoHeaders   string         `json:"pseudo_header_order"`
	FirstHeaders    *HeaderBlock   `json:"first_headers_frame,omitempty"`
	InitialFrames   []FrameSummary `json:"initial_frames"`
	HeaderTableSize uint32         `json:"-"`
}

// Tracker consumes the client->server byte stream of one connection.
type Tracker struct {
	mu        sync.Mutex
	buf       []byte
	gotPrefix bool
	broken    bool
	dec       *hpack.Decoder
	// pending header block (HEADERS + CONTINUATION)
	pending      []byte
	pendingBlock *HeaderBlock

	settings      []Setting
	settingsDone  bool
	windowUpdate  uint32
	priorities    []Priority
	firstHeaders  *HeaderBlock
	initialFrames []FrameSummary
	blocks        []*HeaderBlock
}

// NewTracker returns a new HTTP/2 tracker.
func NewTracker() *Tracker {
	return &Tracker{dec: hpack.NewDecoder(65536, nil)}
}

// Write feeds bytes read from the client. It never fails.
func (t *Tracker) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.broken {
		return len(p), nil
	}
	t.buf = append(t.buf, p...)
	t.parse()
	return len(p), nil
}

func (t *Tracker) parse() {
	if !t.gotPrefix {
		if len(t.buf) < len(preface) {
			return
		}
		if string(t.buf[:len(preface)]) != preface {
			t.broken = true
			return
		}
		t.buf = t.buf[len(preface):]
		t.gotPrefix = true
	}
	for len(t.buf) >= 9 {
		length := int(t.buf[0])<<16 | int(t.buf[1])<<8 | int(t.buf[2])
		if len(t.buf) < 9+length {
			if length > 1<<24 {
				t.broken = true
			}
			return
		}
		typ, flags := t.buf[3], t.buf[4]
		sid := binary.BigEndian.Uint32(t.buf[5:9]) & 0x7fffffff
		payload := t.buf[9 : 9+length]
		t.frame(typ, flags, sid, payload)
		t.buf = t.buf[9+length:]
	}
	if cap(t.buf) > 1<<20 && len(t.buf) < 1<<16 {
		t.buf = append([]byte(nil), t.buf...)
	}
}

func (t *Tracker) frame(typ, flags byte, sid uint32, payload []byte) {
	if t.firstHeaders == nil && len(t.initialFrames) < 32 {
		name := frameNames[typ]
		if name == "" {
			name = "UNKNOWN_" + strconv.Itoa(int(typ))
		}
		t.initialFrames = append(t.initialFrames, FrameSummary{Type: name, StreamID: sid, Length: len(payload), Flags: flags})
	}
	switch typ {
	case frameSettings:
		if flags&0x1 != 0 || t.settingsDone {
			return // ACK or later settings
		}
		for i := 0; i+6 <= len(payload); i += 6 {
			id := binary.BigEndian.Uint16(payload[i:])
			v := binary.BigEndian.Uint32(payload[i+2:])
			n := settingNames[id]
			if n == "" {
				n = "UNKNOWN_" + strconv.Itoa(int(id))
			}
			t.settings = append(t.settings, Setting{ID: id, Name: n, Value: v})
		}
		t.settingsDone = true
	case frameWindowUpdate:
		if sid == 0 && t.firstHeaders == nil && len(payload) >= 4 {
			t.windowUpdate += binary.BigEndian.Uint32(payload) & 0x7fffffff
		}
	case framePriority:
		if t.firstHeaders == nil && len(payload) >= 5 {
			t.priorities = append(t.priorities, parsePriority(sid, payload))
		}
	case frameHeaders:
		hb := &HeaderBlock{StreamID: sid}
		p := payload
		var pad int
		if flags&0x8 != 0 { // PADDED
			if len(p) < 1 {
				return
			}
			pad = int(p[0])
			p = p[1:]
			hb.Flags = append(hb.Flags, "PADDED")
		}
		if flags&0x20 != 0 { // PRIORITY
			if len(p) < 5 {
				return
			}
			pr := parsePriority(sid, p)
			hb.Priority = &pr
			p = p[5:]
			hb.Flags = append(hb.Flags, "PRIORITY")
		}
		if flags&0x1 != 0 {
			hb.Flags = append(hb.Flags, "END_STREAM")
		}
		if flags&0x4 != 0 {
			hb.Flags = append(hb.Flags, "END_HEADERS")
		}
		if pad > len(p) {
			return
		}
		p = p[:len(p)-pad]
		t.pending = append(t.pending[:0], p...)
		t.pendingBlock = hb
		if flags&0x4 != 0 {
			t.finishBlock()
		}
	case frameContinuation:
		if t.pendingBlock == nil {
			return
		}
		t.pending = append(t.pending, payload...)
		if flags&0x4 != 0 {
			t.finishBlock()
		}
	}
}

func (t *Tracker) finishBlock() {
	hb := t.pendingBlock
	t.pendingBlock = nil
	fields, err := t.dec.DecodeFull(t.pending)
	if err != nil {
		t.broken = true
		return
	}
	for _, f := range fields {
		hb.Headers = append(hb.Headers, Header{Name: f.Name, Value: f.Value})
		switch f.Name {
		case ":method":
			hb.method = f.Value
		case ":path":
			hb.path = f.Value
		}
	}
	if t.firstHeaders == nil {
		t.firstHeaders = hb
	}
	t.blocks = append(t.blocks, hb)
	if len(t.blocks) > 64 {
		t.blocks = t.blocks[len(t.blocks)-64:]
	}
}

func parsePriority(sid uint32, p []byte) Priority {
	dep := binary.BigEndian.Uint32(p)
	return Priority{StreamID: sid, Exclusive: dep&0x80000000 != 0, DependsOn: dep & 0x7fffffff, Weight: int(p[4]) + 1}
}

// Fingerprint returns the connection-level fingerprint, or nil if the
// connection preface/first HEADERS frame have not been seen yet.
func (t *Tracker) Fingerprint() *Fingerprint {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.gotPrefix || t.firstHeaders == nil {
		return nil
	}
	f := &Fingerprint{
		Settings:       t.settings,
		WindowUpdate:   t.windowUpdate,
		PriorityFrames: t.priorities,
		FirstHeaders:   t.firstHeaders,
		InitialFrames:  t.initialFrames,
	}
	var s []string
	for _, st := range t.settings {
		s = append(s, fmt.Sprintf("%d:%d", st.ID, st.Value))
	}
	wu := "00"
	if t.windowUpdate > 0 {
		wu = strconv.FormatUint(uint64(t.windowUpdate), 10)
	}
	pr := "0"
	if len(t.priorities) > 0 {
		var ps []string
		for _, p := range t.priorities {
			ex := 0
			if p.Exclusive {
				ex = 1
			}
			ps = append(ps, fmt.Sprintf("%d:%d:%d:%d", p.StreamID, ex, p.DependsOn, p.Weight))
		}
		pr = strings.Join(ps, ",")
	}
	var pseudo []string
	for _, h := range t.firstHeaders.Headers {
		if strings.HasPrefix(h.Name, ":") {
			pseudo = append(pseudo, h.Name[1:2])
		}
	}
	f.PseudoHeaders = strings.Join(pseudo, ",")
	f.Akamai = strings.Join([]string{strings.Join(s, ";"), wu, pr, f.PseudoHeaders}, "|")
	sum := md5.Sum([]byte(f.Akamai))
	f.AkamaiHash = hex.EncodeToString(sum[:])
	return f
}

// RequestHeaders returns the wire-order header block for the oldest not yet
// claimed request matching method and path.
func (t *Tracker) RequestHeaders(method, path string) *HeaderBlock {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range t.blocks {
		if !b.used && b.method == method && b.path == path {
			b.used = true
			return b
		}
	}
	return nil
}
