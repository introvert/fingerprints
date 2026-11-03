// Package quicfp passively decrypts QUIC Initial packets (whose keys are
// derived from the public Destination Connection ID) to recover the client's
// TLS ClientHello and QUIC-level traits, producing a QUIC/HTTP3 fingerprint.
package quicfp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/introvert/fingerprints/internal/tlsfp"
)

var (
	saltV1 = mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	saltV2 = mustHex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
)

const (
	versionV1 = 0x00000001
	versionV2 = 0x6b3343cf
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Fingerprint describes the client's QUIC Initial flight.
type Fingerprint struct {
	Version         string             `json:"version"`
	DCIDLength      int                `json:"dcid_length"`
	SCIDLength      int                `json:"scid_length"`
	TokenLength     int                `json:"token_length"`
	InitialPackets  int                `json:"initial_packets"`
	Datagrams       []int              `json:"datagram_sizes"`
	PacketNumbers   []uint64           `json:"packet_numbers"`
	PacketNumberLen []int              `json:"packet_number_lengths"`
	Frames          [][]string         `json:"frames_per_packet"`
	CryptoFrames    int                `json:"crypto_frames"`
	CryptoOrdered   bool               `json:"crypto_in_order"`
	Coalesced       bool               `json:"coalesced_packets"`
	FirstSeen       time.Time          `json:"first_seen"`
	ClientHelloMS   float64            `json:"client_hello_complete_ms"`
	TLS             *tlsfp.Fingerprint `json:"tls,omitempty"`
	TLSError        string             `json:"tls_error,omitempty"`
	// QUICFingerprint summarises transport traits:
	// version|dcid_len|scid_len|transport params order (ids)
	QUICFingerprint     string   `json:"quic_fingerprint"`
	TransportParamOrder []string `json:"transport_parameter_order"`
}

type state struct {
	fp       *Fingerprint
	dcid     string
	crypto   map[uint64][]byte
	lastOff  uint64
	ordered  bool
	done     bool
	lastSeen time.Time
}

// Table tracks Initial flights by client address.
type Table struct {
	mu sync.Mutex
	m  map[string]*state
}

// NewTable returns an empty table.
func NewTable() *Table { return &Table{m: map[string]*state{}} }

// Lookup returns the fingerprint for a client address ("ip:port").
func (t *Table) Lookup(addr string) *Fingerprint {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.m[addr]; ok && s.done {
		return s.fp
	}
	return nil
}

// Observe processes one datagram received from addr.
func (t *Table) Observe(addr string, d []byte) {
	if len(d) < 7 || d[0]&0x80 == 0 { // short header: not an Initial
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[addr]
	if s != nil && s.done {
		return
	}
	pkts := 0
	for len(d) > 0 && d[0]&0x80 != 0 {
		n, err := t.packet(addr, d, &s, len(d))
		if err != nil || n <= 0 {
			break
		}
		pkts++
		d = d[n:]
	}
	if s != nil && pkts > 1 {
		s.fp.Coalesced = true
	}
	if len(t.m) > 20000 {
		cut := time.Now().Add(-2 * time.Minute)
		for k, v := range t.m {
			if v.lastSeen.Before(cut) {
				delete(t.m, k)
			}
		}
	}
}

func (t *Table) packet(addr string, b []byte, sp **state, dgram int) (int, error) {
	if len(b) < 7 {
		return 0, errors.New("short")
	}
	version := binary.BigEndian.Uint32(b[1:5])
	if version == 0 {
		return 0, errors.New("version negotiation")
	}
	off := 5
	dl := int(b[off])
	off++
	if len(b) < off+dl+1 {
		return 0, errors.New("short dcid")
	}
	dcid := b[off : off+dl]
	off += dl
	sl := int(b[off])
	off++
	if len(b) < off+sl {
		return 0, errors.New("short scid")
	}
	off += sl
	ptype := (b[0] >> 4) & 3
	isInitial := (version == versionV2 && ptype == 1) || (version != versionV2 && ptype == 0)
	tokenLen := 0
	if isInitial {
		tl, n, ok := tlsfp.ReadVarint(b[off:])
		if !ok {
			return 0, errors.New("token len")
		}
		off += n
		tokenLen = int(tl)
		off += tokenLen
	}
	length, n, ok := tlsfp.ReadVarint(b[min(off, len(b)):])
	if !ok {
		return 0, errors.New("length")
	}
	off += n
	end := off + int(length)
	if end > len(b) {
		return 0, errors.New("truncated packet")
	}
	if !isInitial || (version != versionV1 && version != versionV2) {
		return end, nil
	}
	s := *sp
	if s == nil {
		s = &state{fp: &Fingerprint{FirstSeen: time.Now(), DCIDLength: dl, SCIDLength: sl, TokenLength: tokenLen}, dcid: hex.EncodeToString(dcid), crypto: map[uint64][]byte{}, ordered: true}
		s.fp.Version = fmt.Sprintf("0x%08x", version)
		if version == versionV1 {
			s.fp.Version = "v1"
		} else if version == versionV2 {
			s.fp.Version = "v2"
		}
		t.m[addr] = s
		*sp = s
	} else if s.dcid != hex.EncodeToString(dcid) {
		return end, nil // different connection attempt from the same port
	}
	s.lastSeen = time.Now()
	payload, pn, pnLen, err := decryptInitial(version, dcid, b[:end], off)
	if err != nil {
		return end, nil
	}
	s.fp.InitialPackets++
	s.fp.Datagrams = append(s.fp.Datagrams, dgram)
	s.fp.PacketNumbers = append(s.fp.PacketNumbers, pn)
	s.fp.PacketNumberLen = append(s.fp.PacketNumberLen, pnLen)
	s.fp.Frames = append(s.fp.Frames, s.frames(payload))
	s.tryClientHello()
	return end, nil
}

func (s *state) frames(p []byte) []string {
	var out []string
	pad := 0
	flushPad := func() {
		if pad > 0 {
			out = append(out, fmt.Sprintf("PADDING(%d)", pad))
			pad = 0
		}
	}
	for len(p) > 0 {
		ft, n, ok := tlsfp.ReadVarint(p)
		if !ok {
			break
		}
		if ft == 0 {
			pad++
			p = p[n:]
			continue
		}
		flushPad()
		p = p[n:]
		switch ft {
		case 0x01:
			out = append(out, "PING")
		case 0x02, 0x03:
			var vals [4]uint64
			for i := range vals {
				v, n, ok := tlsfp.ReadVarint(p)
				if !ok {
					return out
				}
				vals[i] = v
				p = p[n:]
			}
			for i := uint64(0); i < vals[2]*2; i++ {
				_, n, ok := tlsfp.ReadVarint(p)
				if !ok {
					return out
				}
				p = p[n:]
			}
			if ft == 0x03 {
				for i := 0; i < 3; i++ {
					_, n, _ := tlsfp.ReadVarint(p)
					p = p[n:]
				}
			}
			out = append(out, "ACK")
		case 0x06:
			o, n1, ok1 := tlsfp.ReadVarint(p)
			if !ok1 {
				return out
			}
			l, n2, ok2 := tlsfp.ReadVarint(p[n1:])
			if !ok2 || uint64(len(p)-n1-n2) < l {
				return out
			}
			data := p[n1+n2 : n1+n2+int(l)]
			s.crypto[o] = append([]byte(nil), data...)
			if o < s.lastOff {
				s.ordered = false
			}
			s.lastOff = o
			s.fp.CryptoFrames++
			out = append(out, fmt.Sprintf("CRYPTO(%d+%d)", o, l))
			p = p[n1+n2+int(l):]
		case 0x1c, 0x1d:
			out = append(out, "CONNECTION_CLOSE")
			return out
		default:
			out = append(out, fmt.Sprintf("0x%x", ft))
			return out
		}
	}
	flushPad()
	return out
}

func (s *state) tryClientHello() {
	offs := make([]uint64, 0, len(s.crypto))
	for o := range s.crypto {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var buf []byte
	for _, o := range offs {
		if o > uint64(len(buf)) {
			return // gap
		}
		d := s.crypto[o]
		if o+uint64(len(d)) > uint64(len(buf)) {
			buf = append(buf[:o], d...)
		}
	}
	ch, err := tlsfp.ParseHandshake(buf)
	if errors.Is(err, tlsfp.ErrIncomplete) {
		return
	}
	s.done = true
	s.fp.CryptoOrdered = s.ordered
	s.fp.ClientHelloMS = float64(time.Since(s.fp.FirstSeen).Microseconds()) / 1000
	if err != nil {
		s.fp.TLSError = err.Error()
		return
	}
	s.fp.TLS = ch.Fingerprint(true)
	// Browsers shuffle transport parameter order, so the fingerprint uses the
	// sorted ids; the original order is kept in TransportParamOrder.
	var ids []uint64
	grease := 0
	for _, p := range ch.QUICParams {
		if p.GREASE {
			grease++
			s.fp.TransportParamOrder = append(s.fp.TransportParamOrder, "GREASE")
			continue
		}
		ids = append(ids, p.ID)
		s.fp.TransportParamOrder = append(s.fp.TransportParamOrder, fmt.Sprintf("%x", p.ID))
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	hexIDs := make([]string, len(ids))
	for i, id := range ids {
		hexIDs[i] = fmt.Sprintf("%x", id)
	}
	s.fp.QUICFingerprint = fmt.Sprintf("%s|%d|%d|%s|grease=%d", s.fp.Version, s.fp.DCIDLength, s.fp.SCIDLength, strings.Join(hexIDs, "-"), grease)
}

func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

// decryptInitial removes header protection and decrypts a client Initial
// packet. pnOff is the offset of the packet number field.
func decryptInitial(version uint32, dcid, pkt []byte, pnOff int) ([]byte, uint64, int, error) {
	salt, lk, li, lh := saltV1, "quic key", "quic iv", "quic hp"
	if version == versionV2 {
		salt, lk, li, lh = saltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, 0, 0, err
	}
	client := expandLabel(initial, "client in", 32)
	key, iv, hp := expandLabel(client, lk, 16), expandLabel(client, li, 12), expandLabel(client, lh, 16)
	if len(pkt) < pnOff+4+16 {
		return nil, 0, 0, errors.New("packet too short for sample")
	}
	hb, err := aes.NewCipher(hp)
	if err != nil {
		return nil, 0, 0, err
	}
	mask := make([]byte, 16)
	hb.Encrypt(mask, pkt[pnOff+4:pnOff+20])
	hdr := append([]byte(nil), pkt[:pnOff+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, 0, err
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	pt, err := gcm.Open(nil, nonce, pkt[pnOff+pnLen:], hdr)
	return pt, pn, pnLen, err
}

// TeeConn wraps a PacketConn and feeds received datagrams to a Table.
type TeeConn struct {
	net.PacketConn
	Table *Table
}

// ReadFrom implements net.PacketConn.
func (c *TeeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 && addr != nil {
		c.Table.Observe(addr.String(), p[:n])
	}
	return n, addr, err
}

// SyscallConn exposes the underlying socket for buffer inspection.
func (c *TeeConn) SyscallConn() (syscall.RawConn, error) {
	if s, ok := c.PacketConn.(syscall.Conn); ok {
		return s.SyscallConn()
	}
	return nil, errors.New("quicfp: no syscall conn")
}

// SetReadBuffer passes buffer tuning through to the wrapped socket.
func (c *TeeConn) SetReadBuffer(n int) error {
	if s, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return s.SetReadBuffer(n)
	}
	return nil
}

// SetWriteBuffer passes buffer tuning through to the wrapped socket.
func (c *TeeConn) SetWriteBuffer(n int) error {
	if s, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return s.SetWriteBuffer(n)
	}
	return nil
}
