package quicfp

// Passive decryption of the client's 1-RTT (application) packets. The server
// logs its own TLS secrets (KeyLogWriter); with CLIENT_TRAFFIC_SECRET_0 the
// client's short-header packets can be decrypted in the UDP tap, which gives
// the raw HTTP/3 control stream (SETTINGS in wire order, stream types) and
// request streams (QPACK field lines in wire order with their encodings).
// quic-go itself exposes neither.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/quic-go/qpack"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/introvert/fingerprints/internal/tlsfp"
)

const (
	maxStreamBytes = 64 << 10
	maxAppBytes    = 512 << 10
	maxStreams     = 64
	maxKeys        = 20000
)

// keyLog collects CLIENT_TRAFFIC_SECRET_0 by client random.
type keyLog struct {
	mu   sync.Mutex
	keys map[string][]byte
	buf  []byte
}

func (k *keyLog) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.buf = append(k.buf, p...)
	for {
		i := bytes.IndexByte(k.buf, '\n')
		if i < 0 {
			break
		}
		f := strings.Fields(string(k.buf[:i]))
		k.buf = k.buf[i+1:]
		if len(f) == 3 && f[0] == "CLIENT_TRAFFIC_SECRET_0" {
			if sec, err := hex.DecodeString(f[2]); err == nil {
				if len(k.keys) >= maxKeys {
					for key := range k.keys { // bounded: drop arbitrary old entries
						delete(k.keys, key)
						if len(k.keys) < maxKeys*9/10 {
							break
						}
					}
				}
				k.keys[strings.ToLower(f[1])] = sec
			}
		}
	}
	if len(k.buf) > 4096 {
		k.buf = nil
	}
	return len(p), nil
}

func (k *keyLog) take(clientRandom string) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := k.keys[clientRandom]
	delete(k.keys, clientRandom)
	return s
}

type keySet struct {
	name   string
	aead   cipher.AEAD
	iv     []byte
	mask   func(sample []byte) []byte
	secret []byte
	hash   func() hash.Hash
	keyLen int
	chacha bool
}

func expandLabelH(h func() hash.Hash, secret []byte, l string, n int) []byte {
	full := "tls13 " + l
	info := append([]byte{byte(n >> 8), byte(n), byte(len(full))}, full...)
	info = append(info, 0)
	b, err := hkdf.Expand(h, secret, string(info), n)
	if err != nil {
		return nil
	}
	return b
}

func newAEAD(key []byte, chacha bool) cipher.AEAD {
	if chacha {
		a, err := chacha20poly1305.New(key)
		if err != nil {
			return nil
		}
		return a
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	g, _ := cipher.NewGCM(b)
	return g
}

// next derives the keys of the following key phase (RFC 9001 6.1); the
// header protection key does not change.
func (k *keySet) next() *keySet {
	sec := expandLabelH(k.hash, k.secret, "quic ku", len(k.secret))
	if sec == nil {
		return nil
	}
	n := *k
	n.secret = sec
	n.aead = newAEAD(expandLabelH(k.hash, sec, "quic key", k.keyLen), k.chacha)
	n.iv = expandLabelH(k.hash, sec, "quic iv", 12)
	if n.aead == nil || n.iv == nil {
		return nil
	}
	return &n
}

func deriveKeySets(secret []byte) []*keySet {
	var out []*keySet
	mk := func(h func() hash.Hash, name string, keyLen int, chacha bool) {
		label := func(l string, n int) []byte {
			full := "tls13 " + l
			info := append([]byte{byte(n >> 8), byte(n), byte(len(full))}, full...)
			info = append(info, 0)
			b, err := hkdf.Expand(h, secret, string(info), n)
			if err != nil {
				return nil
			}
			return b
		}
		key, iv, hp := label("quic key", keyLen), label("quic iv", 12), label("quic hp", keyLen)
		if key == nil {
			return
		}
		ks := &keySet{name: name, iv: iv, secret: secret, hash: h, keyLen: keyLen, chacha: chacha}
		if chacha {
			a, err := chacha20poly1305.New(key)
			if err != nil {
				return
			}
			ks.aead = a
			ks.mask = func(sample []byte) []byte {
				c, err := chacha20.NewUnauthenticatedCipher(hp, sample[4:16])
				if err != nil {
					return nil
				}
				c.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
				m := make([]byte, 5)
				c.XORKeyStream(m, m)
				return m
			}
		} else {
			b, err := aes.NewCipher(key)
			if err != nil {
				return
			}
			ks.aead, _ = cipher.NewGCM(b)
			hb, err := aes.NewCipher(hp)
			if err != nil {
				return
			}
			ks.mask = func(sample []byte) []byte {
				m := make([]byte, 16)
				hb.Encrypt(m, sample)
				return m
			}
		}
		out = append(out, ks)
	}
	switch len(secret) {
	case 32:
		mk(sha256.New, "TLS_AES_128_GCM_SHA256", 16, false)
		mk(sha256.New, "TLS_CHACHA20_POLY1305_SHA256", 32, true)
	case 48:
		mk(sha512.New384, "TLS_AES_256_GCM_SHA384", 32, false)
	}
	return out
}

type streamBuf struct {
	chunks map[uint64][]byte
	size   int
	order  int // creation order
}

type appState struct {
	candidates []*keySet
	keys       *keySet // current phase
	prevKeys   *keySet // previous phase (delayed packets)
	nextKeys   *keySet
	phase      byte
	keyUpdates int
	largestPN  int64
	streams    map[uint64]*streamBuf
	total      int
	packets    int
	failures   int
	frameLog   [][]string
	used       map[uint64]bool
}

func newAppState(secret []byte) *appState {
	return &appState{candidates: deriveKeySets(secret), largestPN: -1, streams: map[uint64]*streamBuf{}, used: map[uint64]bool{}}
}

// decodePN expands a truncated packet number (RFC 9000 A.3).
func decodePN(largest int64, truncated uint64, pnLen int) uint64 {
	expected := uint64(largest + 1)
	win := uint64(1) << (8 * pnLen)
	hwin, mask := win/2, win-1
	cand := (expected &^ mask) | truncated
	switch {
	case cand+hwin <= expected && cand < (1<<62)-win:
		return cand + win
	case cand > expected+hwin && cand >= win:
		return cand - win
	}
	return cand
}

func (a *appState) decrypt(pkt []byte, cidLen int) ([]byte, bool) {
	pnOff := 1 + cidLen
	if len(pkt) < pnOff+4+16 {
		return nil, false
	}
	try := a.candidates
	if a.keys != nil {
		try = []*keySet{a.keys}
	}
	for _, ks := range try {
		m := ks.mask(pkt[pnOff+4 : pnOff+20])
		if m == nil {
			continue
		}
		hdr := append([]byte(nil), pkt[:pnOff+4]...)
		hdr[0] ^= m[0] & 0x1f
		phase := (hdr[0] >> 2) & 1
		update := false
		if a.keys != nil && phase != a.phase {
			// either a key update by the client or a delayed old-phase packet
			if a.nextKeys == nil {
				a.nextKeys = a.keys.next()
			}
			if a.nextKeys == nil {
				return nil, false
			}
			ks, update = a.nextKeys, true
		}
		pnLen := int(hdr[0]&3) + 1
		var tpn uint64
		for i := 0; i < pnLen; i++ {
			hdr[pnOff+i] ^= m[1+i]
			tpn = tpn<<8 | uint64(hdr[pnOff+i])
		}
		pn := decodePN(a.largestPN, tpn, pnLen)
		nonce := append([]byte(nil), ks.iv...)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
		}
		pt, err := ks.aead.Open(nil, nonce, pkt[pnOff+pnLen:], hdr[:pnOff+pnLen])
		if err != nil && update && a.prevKeys != nil {
			if pt2, err2 := a.prevKeys.aead.Open(nil, nonce, pkt[pnOff+pnLen:], hdr[:pnOff+pnLen]); err2 == nil {
				return pt2, true // delayed packet from the previous phase
			}
		}
		if err != nil {
			continue
		}
		if update {
			a.prevKeys, a.nextKeys = a.keys, nil
			a.phase ^= 1
			a.keyUpdates++
		} else if a.keys == nil {
			a.phase = phase
		}
		a.keys = ks
		if int64(pn) > a.largestPN {
			a.largestPN = int64(pn)
		}
		return pt, true
	}
	return nil, false
}

func skipVarints(p []byte, n int) ([]byte, bool) {
	for i := 0; i < n; i++ {
		_, k, ok := tlsfp.ReadVarint(p)
		if !ok {
			return nil, false
		}
		p = p[k:]
	}
	return p, true
}

var appFrameNames = map[uint64]string{0x01: "PING", 0x02: "ACK", 0x03: "ACK_ECN", 0x04: "RESET_STREAM", 0x05: "STOP_SENDING",
	0x06: "CRYPTO", 0x07: "NEW_TOKEN", 0x10: "MAX_DATA", 0x11: "MAX_STREAM_DATA", 0x12: "MAX_STREAMS", 0x13: "MAX_STREAMS",
	0x14: "DATA_BLOCKED", 0x15: "STREAM_DATA_BLOCKED", 0x16: "STREAMS_BLOCKED", 0x17: "STREAMS_BLOCKED",
	0x18: "NEW_CONNECTION_ID", 0x19: "RETIRE_CONNECTION_ID", 0x1a: "PATH_CHALLENGE", 0x1b: "PATH_RESPONSE",
	0x1c: "CONNECTION_CLOSE", 0x1d: "CONNECTION_CLOSE", 0x1e: "HANDSHAKE_DONE", 0x30: "DATAGRAM", 0x31: "DATAGRAM", 0xaf: "ACK_FREQUENCY"}

// frames walks a decrypted 1-RTT payload, collecting STREAM data.
func (a *appState) frames(p []byte) []string {
	var log []string
	pad := 0
	for len(p) > 0 {
		ft, n, ok := tlsfp.ReadVarint(p)
		if !ok {
			return log
		}
		p = p[n:]
		if ft == 0 {
			pad++
			continue
		}
		if pad > 0 {
			log = append(log, fmt.Sprintf("PADDING(%d)", pad))
			pad = 0
		}
		switch {
		case ft >= 0x08 && ft <= 0x0f:
			id, k, ok := tlsfp.ReadVarint(p)
			if !ok {
				return log
			}
			p = p[k:]
			var off uint64
			if ft&0x04 != 0 {
				if off, k, ok = tlsfp.ReadVarint(p); !ok {
					return log
				}
				p = p[k:]
			}
			l := uint64(len(p))
			if ft&0x02 != 0 {
				if l, k, ok = tlsfp.ReadVarint(p); !ok || uint64(len(p)-k) < l {
					return log
				}
				p = p[k:]
			}
			a.addStream(id, off, p[:l])
			log = append(log, fmt.Sprintf("STREAM(%d)", id))
			p = p[l:]
			continue
		case ft == 0x01 || ft == 0x1e:
		case ft == 0x02 || ft == 0x03:
			var vals [4]uint64
			for i := range vals {
				v, k, ok := tlsfp.ReadVarint(p)
				if !ok {
					return log
				}
				vals[i] = v
				p = p[k:]
			}
			if vals[2] > 256 {
				return log
			}
			if p, ok = skipVarints(p, int(vals[2])*2); !ok {
				return log
			}
			if ft == 0x03 {
				if p, ok = skipVarints(p, 3); !ok {
					return log
				}
			}
		case ft == 0x04:
			p, ok = skipVarints(p, 3)
		case ft == 0x05 || ft == 0x11 || ft == 0x15:
			p, ok = skipVarints(p, 2)
		case ft == 0x10 || ft == 0x12 || ft == 0x13 || ft == 0x14 || ft == 0x16 || ft == 0x17 || ft == 0x19:
			p, ok = skipVarints(p, 1)
		case ft == 0x06 || ft == 0x07 || ft == 0x31:
			if ft == 0x06 {
				if p, ok = skipVarints(p, 1); !ok {
					return log
				}
			}
			l, k, ok2 := tlsfp.ReadVarint(p)
			if !ok2 || uint64(len(p)-k) < l {
				return log
			}
			p = p[k+int(l):]
		case ft == 0x18:
			if p, ok = skipVarints(p, 2); !ok || len(p) < 1 || len(p) < 1+int(p[0])+16 {
				return log
			}
			p = p[1+int(p[0])+16:]
		case ft == 0x1a || ft == 0x1b:
			if len(p) < 8 {
				return log
			}
			p = p[8:]
		case ft == 0x1c || ft == 0x1d:
			log = append(log, "CONNECTION_CLOSE")
			return log
		case ft == 0x30:
			p = nil
		case ft == 0xaf:
			p, ok = skipVarints(p, 4)
		default:
			log = append(log, fmt.Sprintf("0x%x", ft))
			return log
		}
		if !ok {
			return log
		}
		log = append(log, appFrameNames[ft])
	}
	if pad > 0 {
		log = append(log, fmt.Sprintf("PADDING(%d)", pad))
	}
	return log
}

func (a *appState) addStream(id, off uint64, data []byte) {
	if id%4 != 0 && id%4 != 2 { // only client-initiated streams
		return
	}
	s := a.streams[id]
	if s == nil {
		if len(a.streams) >= maxStreams {
			return
		}
		s = &streamBuf{chunks: map[uint64][]byte{}, order: len(a.streams)}
		a.streams[id] = s
	}
	if s.size+len(data) > maxStreamBytes || a.total+len(data) > maxAppBytes || off > maxStreamBytes {
		return
	}
	if _, dup := s.chunks[off]; dup {
		return
	}
	s.chunks[off] = append([]byte(nil), data...)
	s.size += len(data)
	a.total += len(data)
}

// contiguous returns the stream bytes available from offset 0.
func (s *streamBuf) contiguous() []byte {
	offs := make([]uint64, 0, len(s.chunks))
	for o := range s.chunks {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var buf []byte
	for _, o := range offs {
		if o > uint64(len(buf)) {
			break
		}
		d := s.chunks[o]
		if end := o + uint64(len(d)); end > uint64(len(buf)) {
			buf = append(buf[:o], d...)
		}
	}
	return buf
}

// ---- HTTP/3 ----

var h3SettingNames = map[uint64]string{0x01: "QPACK_MAX_TABLE_CAPACITY", 0x06: "MAX_FIELD_SECTION_SIZE", 0x07: "QPACK_BLOCKED_STREAMS",
	0x08: "ENABLE_CONNECT_PROTOCOL", 0x33: "H3_DATAGRAM", 0x2b603742: "ENABLE_WEBTRANSPORT", 0xc671706a: "WEBTRANSPORT_MAX_SESSIONS",
	0x14e9cd29: "WEBTRANSPORT_MAX_SESSIONS_DRAFT"}

var h3StreamTypes = map[uint64]string{0x00: "control", 0x01: "push", 0x02: "qpack_encoder", 0x03: "qpack_decoder", 0x54: "webtransport"}

func isH3Grease(v uint64) bool { return v >= 0x21 && (v-0x21)%0x1f == 0 }

// H3Setting is one SETTINGS parameter in wire order.
type H3Setting struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

// H3Control describes the client's HTTP/3 control-plane behaviour.
type H3Control struct {
	Settings        []H3Setting `json:"settings"`
	UniStreamTypes  []string    `json:"uni_stream_types"`
	ControlFrames   []string    `json:"control_frames"`
	SettingsString  string      `json:"settings_fingerprint"`
	FirstPacketsLog [][]string  `json:"first_1rtt_packets_frames,omitempty"`
	CipherSuite     string      `json:"decrypted_with,omitempty"`
	KeyUpdates      int         `json:"client_key_updates"`
}

// QPACKRepr describes the wire encoding of one QPACK field line.
type QPACKRepr struct {
	Type        string `json:"type"` // indexed | indexed_post_base | literal_name_ref | literal_post_base_name_ref | literal_name
	Static      bool   `json:"static,omitempty"`
	Index       uint64 `json:"index,omitempty"`
	NeverIndex  bool   `json:"never_index,omitempty"`
	NameHuffman bool   `json:"name_huffman,omitempty"`
	Huffman     bool   `json:"value_huffman,omitempty"`
	Code        string `json:"code"`
}

// H3Header is a decoded request header in wire order.
type H3Header struct {
	Name  string     `json:"name"`
	Value string     `json:"value"`
	QPACK *QPACKRepr `json:"qpack,omitempty"`
}

// H3Request is the decoded HEADERS of one request stream.
type H3Request struct {
	StreamID         uint64     `json:"stream_id"`
	Headers          []H3Header `json:"headers"`
	QPACKCodes       string     `json:"qpack_codes"`
	RequiredInsert   uint64     `json:"required_insert_count"`
	FramesBeforeHdrs []string   `json:"frames_before_headers,omitempty"`
	method, path     string
}

func readH3Frame(p []byte) (typ uint64, payload, rest []byte, ok bool) {
	t, n, ok1 := tlsfp.ReadVarint(p)
	if !ok1 {
		return 0, nil, nil, false
	}
	l, m, ok2 := tlsfp.ReadVarint(p[n:])
	if !ok2 || uint64(len(p)-n-m) < l {
		return 0, nil, nil, false
	}
	return t, p[n+m : n+m+int(l)], p[n+m+int(l):], true
}

func h3FrameName(t uint64) string {
	switch {
	case t == 0x00:
		return "DATA"
	case t == 0x01:
		return "HEADERS"
	case t == 0x03:
		return "CANCEL_PUSH"
	case t == 0x04:
		return "SETTINGS"
	case t == 0x07:
		return "GOAWAY"
	case t == 0x0d:
		return "MAX_PUSH_ID"
	case t == 0xf0700:
		return "PRIORITY_UPDATE_REQUEST"
	case t == 0xf0701:
		return "PRIORITY_UPDATE_PUSH"
	case isH3Grease(t):
		return "GREASE"
	}
	return fmt.Sprintf("0x%x", t)
}

func (a *appState) control() *H3Control {
	c := &H3Control{FirstPacketsLog: a.frameLog}
	if a.keys != nil {
		c.CipherSuite = a.keys.name
	}
	c.KeyUpdates = a.keyUpdates
	ids := make([]uint64, 0, len(a.streams))
	for id := range a.streams {
		if id%4 == 2 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		b := a.streams[id].contiguous()
		st, n, ok := tlsfp.ReadVarint(b)
		if !ok {
			continue
		}
		name := h3StreamTypes[st]
		if isH3Grease(st) {
			name = "GREASE"
		} else if name == "" {
			name = fmt.Sprintf("0x%x", st)
		}
		c.UniStreamTypes = append(c.UniStreamTypes, name)
		if st != 0x00 {
			continue
		}
		p := b[n:]
		for len(p) > 0 && len(c.ControlFrames) < 32 {
			t, payload, rest, ok := readH3Frame(p)
			if !ok {
				break
			}
			c.ControlFrames = append(c.ControlFrames, h3FrameName(t))
			if t == 0x04 && c.Settings == nil {
				c.Settings = []H3Setting{}
				for q := payload; len(q) > 0; {
					id, k, ok1 := tlsfp.ReadVarint(q)
					if !ok1 {
						break
					}
					v, m, ok2 := tlsfp.ReadVarint(q[k:])
					if !ok2 {
						break
					}
					q = q[k+m:]
					nm := h3SettingNames[id]
					if isH3Grease(id) {
						nm = "GREASE"
					} else if nm == "" {
						nm = fmt.Sprintf("0x%x", id)
					}
					c.Settings = append(c.Settings, H3Setting{ID: id, Name: nm, Value: v})
				}
			}
			p = rest
		}
	}
	var parts []string
	for _, s := range c.Settings {
		if isH3Grease(s.ID) {
			parts = append(parts, "GREASE")
		} else {
			parts = append(parts, fmt.Sprintf("%d:%d", s.ID, s.Value))
		}
	}
	c.SettingsString = strings.Join(parts, ";")
	return c
}

func (a *appState) request(id uint64) *H3Request {
	s := a.streams[id]
	if s == nil {
		return nil
	}
	p := s.contiguous()
	r := &H3Request{StreamID: id}
	for len(p) > 0 {
		t, payload, rest, ok := readH3Frame(p)
		if !ok {
			return nil
		}
		if t != 0x01 {
			r.FramesBeforeHdrs = append(r.FramesBeforeHdrs, h3FrameName(t))
			p = rest
			continue
		}
		reps, ric := scanQPACK(payload)
		r.RequiredInsert = ric
		dec := qpack.NewDecoder().Decode(payload)
		var codes []string
		for i := 0; ; i++ {
			hf, err := dec()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil
			}
			h := H3Header{Name: hf.Name, Value: hf.Value}
			if i < len(reps) {
				rp := reps[i]
				h.QPACK = &rp
				codes = append(codes, rp.Code)
			}
			switch hf.Name {
			case ":method":
				r.method = hf.Value
			case ":path":
				r.path = hf.Value
			}
			r.Headers = append(r.Headers, h)
		}
		if len(codes) == len(r.Headers) {
			r.QPACKCodes = strings.Join(codes, ",")
		}
		return r
	}
	return nil
}

func qint(b []byte, prefix uint) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	max := uint64(1)<<prefix - 1
	v := uint64(b[0]) & max
	if v < max {
		return v, 1, true
	}
	var m uint
	for i := 1; i < len(b) && i < 10; i++ {
		v += uint64(b[i]&0x7f) << m
		m += 7
		if b[i]&0x80 == 0 {
			return v, i + 1, true
		}
	}
	return 0, 0, false
}

// qstr skips a QPACK string with an H bit at hbit and a length prefix.
func qstr(b []byte, hbit byte, prefix uint) (bool, int, bool) {
	if len(b) == 0 {
		return false, 0, false
	}
	l, n, ok := qint(b, prefix)
	if !ok || uint64(len(b)-n) < l {
		return false, 0, false
	}
	return b[0]&hbit != 0, n + int(l), true
}

// scanQPACK reports the representation of each field line (RFC 9204 4.5).
func scanQPACK(b []byte) ([]QPACKRepr, uint64) {
	ric, n, ok := qint(b, 8)
	if !ok {
		return nil, 0
	}
	b = b[n:]
	if _, n, ok = qint(b, 7); !ok { // sign + delta base
		return nil, ric
	}
	b = b[n:]
	var out []QPACKRepr
	for len(b) > 0 {
		c := b[0]
		var r QPACKRepr
		switch {
		case c&0x80 != 0:
			idx, n, ok := qint(b, 6)
			if !ok {
				return out, ric
			}
			r = QPACKRepr{Type: "indexed", Static: c&0x40 != 0, Index: idx}
			r.Code = "I" + map[bool]string{true: "s", false: "d"}[r.Static]
			b = b[n:]
		case c&0xc0 == 0x40:
			idx, n, ok := qint(b, 4)
			if !ok {
				return out, ric
			}
			r = QPACKRepr{Type: "literal_name_ref", NeverIndex: c&0x20 != 0, Static: c&0x10 != 0, Index: idx}
			b = b[n:]
			h, m, ok := qstr(b, 0x80, 7)
			if !ok {
				return out, ric
			}
			r.Huffman = h
			b = b[m:]
			r.Code = "L" + map[bool]string{true: "s", false: "d"}[r.Static]
		case c&0xe0 == 0x20:
			nh, m, ok := qstr(b, 0x08, 3)
			if !ok {
				return out, ric
			}
			r = QPACKRepr{Type: "literal_name", NeverIndex: c&0x10 != 0, NameHuffman: nh}
			b = b[m:]
			h, m2, ok := qstr(b, 0x80, 7)
			if !ok {
				return out, ric
			}
			r.Huffman = h
			b = b[m2:]
			r.Code = "Ln"
		case c&0xf0 == 0x10:
			idx, n, ok := qint(b, 4)
			if !ok {
				return out, ric
			}
			r = QPACKRepr{Type: "indexed_post_base", Index: idx, Code: "Ip"}
			b = b[n:]
		default:
			idx, n, ok := qint(b, 3)
			if !ok {
				return out, ric
			}
			r = QPACKRepr{Type: "literal_post_base_name_ref", NeverIndex: c&0x08 != 0, Index: idx}
			b = b[n:]
			h, m, ok := qstr(b, 0x80, 7)
			if !ok {
				return out, ric
			}
			r.Huffman = h
			b = b[m:]
			r.Code = "Lp"
		}
		if r.NeverIndex {
			r.Code += "!"
		}
		if r.Huffman {
			r.Code += "*"
		}
		out = append(out, r)
	}
	return out, ric
}
