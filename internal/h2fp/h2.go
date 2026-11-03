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
	"time"

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
	framePriorityUpd  = 0x10
)

var settingNames = map[uint16]string{
	1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE",
	5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE", 8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES",
}

var frameNames = map[byte]string{
	0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE",
	6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION", 0xa: "ALTSVC", 0xc: "ORIGIN",
	0x10: "PRIORITY_UPDATE",
}

var errCodes = map[uint32]string{0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
	4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL",
	9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}

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
	Name  string     `json:"name"`
	Value string     `json:"value"`
	HPACK *HPACKRepr `json:"hpack,omitempty"`
}

// PriorityUpdate is an RFC 9218 PRIORITY_UPDATE frame.
type PriorityUpdate struct {
	StreamID uint32 `json:"prioritized_stream_id"`
	Value    string `json:"priority_field_value"`
}

// Frame is one entry of the client frame log.
type Frame struct {
	AtMS           float64         `json:"at_ms"`
	Type           string          `json:"type"`
	StreamID       uint32          `json:"stream_id"`
	Length         int             `json:"length"`
	Flags          []string        `json:"flags,omitempty"`
	Settings       []Setting       `json:"settings,omitempty"`
	Increment      uint32          `json:"increment,omitempty"`
	Priority       *Priority       `json:"priority,omitempty"`
	PriorityUpdate *PriorityUpdate `json:"priority_update,omitempty"`
	Headers        []string        `json:"headers,omitempty"`
	ErrorCode      string          `json:"error_code,omitempty"`
	Data           string          `json:"data,omitempty"`
}

// HeaderBlock is a decoded request header block.
type HeaderBlock struct {
	StreamID uint32    `json:"stream_id"`
	Flags    []string  `json:"flags,omitempty"`
	Priority *Priority `json:"priority,omitempty"`
	Headers  []Header  `json:"headers"`
	// HPACKCodes summarises field representations (I=indexed, A=incremental,
	// W=without indexing, N=never indexed; i/n = indexed/new name; *=huffman).
	HPACKCodes       string   `json:"hpack_codes"`
	HPACKSizeUpdates []uint64 `json:"hpack_table_size_updates,omitempty"`
	ReceivedMS       float64  `json:"received_at_ms"`
	method           string
	path             string
	used             bool
}

// Fingerprint is the HTTP/2 connection fingerprint.
type Fingerprint struct {
	Akamai                  string           `json:"akamai_fingerprint"`
	AkamaiHash              string           `json:"akamai_fingerprint_hash"`
	Settings                []Setting        `json:"settings"`
	WindowUpdate            uint32           `json:"connection_window_update"`
	PriorityFrames          []Priority       `json:"priority_frames"`
	PseudoHeaders           string           `json:"pseudo_header_order"`
	FirstHeaders            *HeaderBlock     `json:"first_headers_frame,omitempty"`
	PriorityUpdates         []PriorityUpdate `json:"priority_updates,omitempty"`
	HPACKCodes              string           `json:"hpack_fingerprint"`
	Frames                  []Frame          `json:"frames"`
	FramesTruncated         bool             `json:"frames_truncated,omitempty"`
	PrefaceToFirstHeadersMS float64          `json:"preface_to_first_headers_ms"`
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
	pendingFrame int

	settings      []Setting
	settingsDone  bool
	windowUpdate  uint32
	priorities    []Priority
	firstHeaders  *HeaderBlock
	frames        []Frame
	framesDropped bool
	prioUpdates   []PriorityUpdate
	blocks        []*HeaderBlock
	start         time.Time
	firstHdrAt    time.Time
}

// NewTracker returns a new HTTP/2 tracker.
func NewTracker() *Tracker {
	return &Tracker{dec: hpack.NewDecoder(65536, nil), pendingFrame: -1}
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
		t.start = time.Now()
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
	var fr *Frame
	frIdx := -1
	if len(t.frames) < 256 {
		name := frameNames[typ]
		if name == "" {
			name = "UNKNOWN_" + strconv.Itoa(int(typ))
		}
		t.frames = append(t.frames, Frame{AtMS: msSince(t.start), Type: name, StreamID: sid, Length: len(payload), Flags: flagNames(typ, flags)})
		frIdx = len(t.frames) - 1
		fr = &t.frames[frIdx]
	} else {
		t.framesDropped = true
		fr = &Frame{}
	}
	switch typ {
	case framePriorityUpd:
		if len(payload) >= 4 {
			pu := PriorityUpdate{StreamID: binary.BigEndian.Uint32(payload) & 0x7fffffff, Value: string(payload[4:])}
			fr.PriorityUpdate = &pu
			if len(t.prioUpdates) < 64 {
				t.prioUpdates = append(t.prioUpdates, pu)
			}
		}
	case frameRSTStream:
		if len(payload) >= 4 {
			fr.ErrorCode = errName(binary.BigEndian.Uint32(payload))
		}
	case frameGoAway:
		if len(payload) >= 8 {
			fr.ErrorCode = errName(binary.BigEndian.Uint32(payload[4:]))
		}
	case framePing:
		fr.Data = fmt.Sprintf("%x", payload)
	case frameSettings:
		var list []Setting
		for i := 0; i+6 <= len(payload); i += 6 {
			id := binary.BigEndian.Uint16(payload[i:])
			v := binary.BigEndian.Uint32(payload[i+2:])
			n := settingNames[id]
			if n == "" {
				n = "UNKNOWN_" + strconv.Itoa(int(id))
			}
			list = append(list, Setting{ID: id, Name: n, Value: v})
		}
		fr.Settings = list
		if flags&0x1 == 0 && !t.settingsDone {
			t.settings = list
			t.settingsDone = true
		}
	case frameWindowUpdate:
		if len(payload) >= 4 {
			fr.Increment = binary.BigEndian.Uint32(payload) & 0x7fffffff
			if sid == 0 && t.firstHeaders == nil {
				t.windowUpdate += fr.Increment
			}
		}
	case framePriority:
		if len(payload) >= 5 {
			pr := parsePriority(sid, payload)
			fr.Priority = &pr
			if t.firstHeaders == nil {
				t.priorities = append(t.priorities, pr)
			}
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
		fr.Priority = hb.Priority
		t.pending = append(t.pending[:0], p...)
		t.pendingBlock = hb
		t.pendingFrame = frIdx
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
	reps, sizeUpd := scanHPACK(t.pending)
	hb.HPACKSizeUpdates = sizeUpd
	if len(reps) == len(fields) {
		hb.HPACKCodes = reprString(reps)
	}
	hb.ReceivedMS = msSince(t.start)
	var names []string
	for i, f := range fields {
		h := Header{Name: f.Name, Value: f.Value}
		if len(reps) == len(fields) {
			r := reps[i]
			h.HPACK = &r
		}
		hb.Headers = append(hb.Headers, h)
		names = append(names, f.Name)
		switch f.Name {
		case ":method":
			hb.method = f.Value
		case ":path":
			hb.path = f.Value
		}
	}
	if t.pendingFrame >= 0 && t.pendingFrame < len(t.frames) && t.frames[t.pendingFrame].Type == "HEADERS" {
		t.frames[t.pendingFrame].Headers = names
	}
	if t.firstHeaders == nil {
		t.firstHeaders = hb
		t.firstHdrAt = time.Now()
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
		Settings:                t.settings,
		WindowUpdate:            t.windowUpdate,
		PriorityFrames:          t.priorities,
		FirstHeaders:            t.firstHeaders,
		Frames:                  append([]Frame(nil), t.frames...),
		FramesTruncated:         t.framesDropped,
		PriorityUpdates:         append([]PriorityUpdate(nil), t.prioUpdates...),
		HPACKCodes:              t.firstHeaders.HPACKCodes,
		PrefaceToFirstHeadersMS: float64(t.firstHdrAt.Sub(t.start).Microseconds()) / 1000,
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

func msSince(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(time.Since(t).Microseconds()) / 1000
}

func errName(c uint32) string {
	if n, ok := errCodes[c]; ok {
		return n
	}
	return fmt.Sprintf("0x%x", c)
}

func flagNames(typ, f byte) []string {
	var out []string
	add := func(bit byte, n string) {
		if f&bit != 0 {
			out = append(out, n)
		}
	}
	switch typ {
	case frameSettings, framePing:
		add(0x1, "ACK")
	case frameHeaders:
		add(0x1, "END_STREAM")
		add(0x4, "END_HEADERS")
		add(0x8, "PADDED")
		add(0x20, "PRIORITY")
	case frameData:
		add(0x1, "END_STREAM")
		add(0x8, "PADDED")
	case frameContinuation:
		add(0x4, "END_HEADERS")
	}
	return out
}
