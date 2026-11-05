// Package tlsfp parses raw TLS ClientHello messages and derives the common
// TLS client fingerprints (JA3, JA3N, JA4, JA4_r, JA4_o, peetprint).
package tlsfp

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrIncomplete is returned when more bytes are needed to parse the ClientHello.
var ErrIncomplete = errors.New("tlsfp: incomplete ClientHello")

// Extension is a single ClientHello extension.
type Extension struct {
	ID     uint16 `json:"id"`
	Name   string `json:"name"`
	Length int    `json:"length"`
	// Data holds decoded contents for well known extensions.
	Data any `json:"data,omitempty"`
	// Hex is the raw extension payload (truncated to 1 KiB).
	Hex string `json:"hex,omitempty"`
}

// ClientHello is the decoded ClientHello.
type ClientHello struct {
	RecordVersion      uint16      `json:"-"`
	Version            uint16      `json:"-"`
	Random             []byte      `json:"-"`
	SessionID          []byte      `json:"-"`
	CipherSuites       []uint16    `json:"-"`
	CompressionMethods []uint8     `json:"-"`
	Extensions         []Extension `json:"-"`

	ServerName          string         `json:"-"`
	SupportedGroups     []uint16       `json:"-"`
	ECPointFormats      []uint8        `json:"-"`
	SignatureAlgorithms []uint16       `json:"-"`
	SigAlgsCert         []uint16       `json:"-"`
	ALPN                []string       `json:"-"`
	SupportedVersions   []uint16       `json:"-"`
	KeyShareGroups      []uint16       `json:"-"`
	PSKModes            []uint8        `json:"-"`
	CertCompression     []uint16       `json:"-"`
	ALPS                []string       `json:"-"`
	RecordSizeLimit     int            `json:"-"`
	DelegatedCredSigs   []uint16       `json:"-"`
	HasECH              bool           `json:"-"`
	HasPSK              bool           `json:"-"`
	HasEarlyData        bool           `json:"-"`
	PaddingLen          int            `json:"-"`
	RawLength           int            `json:"-"`
	Raw                 []byte         `json:"-"`
	SessionTicketLen    int            `json:"-"`
	PSKIdentities       int            `json:"-"`
	ECH                 map[string]any `json:"-"`
	QUICParams          []QUICParam    `json:"-"`
}

// QUICParam is one QUIC transport parameter (extension 57).
type QUICParam struct {
	ID     uint64 `json:"id"`
	Name   string `json:"name"`
	Value  any    `json:"value,omitempty"`
	GREASE bool   `json:"grease,omitempty"`
}

// Parse decodes a ClientHello from the raw bytes a client sent at the start of
// a TLS connection (one or more TLS records). It returns ErrIncomplete if the
// buffer does not yet hold the whole handshake message.
func Parse(raw []byte) (*ClientHello, error) {
	// Reassemble handshake bytes from (possibly several) TLS records.
	var hs []byte
	var recVersion uint16
	p := raw
	for {
		if len(p) < 5 {
			return nil, ErrIncomplete
		}
		if p[0] != 0x16 {
			return nil, fmt.Errorf("tlsfp: not a handshake record (type %d)", p[0])
		}
		if recVersion == 0 {
			recVersion = uint16(p[1])<<8 | uint16(p[2])
		}
		n := int(p[3])<<8 | int(p[4])
		if len(p) < 5+n {
			return nil, ErrIncomplete
		}
		hs = append(hs, p[5:5+n]...)
		p = p[5+n:]
		if len(hs) >= 4 {
			need := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) >= 4+need {
				hs = hs[:4+need]
				break
			}
		}
	}
	ch, err := ParseHandshake(hs)
	if ch != nil {
		ch.RecordVersion = recVersion
	}
	return ch, err
}

// ParseHandshake decodes a ClientHello handshake message (without the TLS
// record layer), e.g. reassembled from QUIC CRYPTO frames.
func ParseHandshake(hs []byte) (*ClientHello, error) {
	if len(hs) < 4 {
		return nil, ErrIncomplete
	}
	if hs[0] != 0x01 {
		return nil, fmt.Errorf("tlsfp: not a ClientHello (handshake type %d)", hs[0])
	}
	need := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+need {
		return nil, ErrIncomplete
	}
	hs = hs[:4+need]
	ch := &ClientHello{RawLength: len(hs), Raw: append([]byte(nil), hs...)}
	r := reader(hs[4:])
	var ok bool
	if ch.Version, ok = r.u16(); !ok {
		return nil, errors.New("tlsfp: short version")
	}
	if ch.Random, ok = r.bytes(32); !ok {
		return nil, errors.New("tlsfp: short random")
	}
	if ch.SessionID, ok = r.vec8(); !ok {
		return nil, errors.New("tlsfp: bad session id")
	}
	cs, ok := r.vec16()
	if !ok || len(cs)%2 != 0 {
		return nil, errors.New("tlsfp: bad cipher suites")
	}
	ch.CipherSuites = u16s(cs)
	cm, ok := r.vec8()
	if !ok {
		return nil, errors.New("tlsfp: bad compression methods")
	}
	ch.CompressionMethods = append([]uint8(nil), cm...)
	if len(r) == 0 {
		return ch, nil
	}
	exts, ok := r.vec16()
	if !ok {
		return nil, errors.New("tlsfp: bad extensions block")
	}
	er := reader(exts)
	for len(er) > 0 {
		id, ok1 := er.u16()
		data, ok2 := er.vec16()
		if !ok1 || !ok2 {
			return nil, errors.New("tlsfp: bad extension")
		}
		ext := Extension{ID: id, Name: ExtensionName(id), Length: len(data)}
		ext.Data = ch.decodeExtension(id, data)
		if len(data) > 0 {
			ext.Hex = hex.EncodeToString(data[:min(len(data), 1024)])
		}
		ch.Extensions = append(ch.Extensions, ext)
	}
	return ch, nil
}

func (ch *ClientHello) decodeExtension(id uint16, data []byte) any {
	r := reader(data)
	switch id {
	case 0: // server_name
		list, ok := r.vec16()
		if !ok {
			return nil
		}
		lr := reader(list)
		for len(lr) > 0 {
			t, _ := lr.u8()
			name, ok := lr.vec16()
			if !ok {
				break
			}
			if t == 0 {
				ch.ServerName = string(name)
			}
		}
		return map[string]any{"host_name": ch.ServerName}
	case 10:
		v, _ := r.vec16()
		ch.SupportedGroups = u16s(v)
		return named(ch.SupportedGroups, GroupName)
	case 11:
		v, _ := r.vec8()
		ch.ECPointFormats = append([]uint8(nil), v...)
		return ch.ECPointFormats
	case 13:
		v, _ := r.vec16()
		ch.SignatureAlgorithms = u16s(v)
		return named(ch.SignatureAlgorithms, SigAlgName)
	case 50:
		v, _ := r.vec16()
		ch.SigAlgsCert = u16s(v)
		return named(ch.SigAlgsCert, SigAlgName)
	case 16:
		v, _ := r.vec16()
		ch.ALPN = protoList(v)
		return ch.ALPN
	case 17513, 17613:
		v, _ := r.vec16()
		ch.ALPS = protoList(v)
		return ch.ALPS
	case 43:
		v, _ := r.vec8()
		ch.SupportedVersions = u16s(v)
		return named(ch.SupportedVersions, VersionName)
	case 51:
		v, _ := r.vec16()
		kr := reader(v)
		var out []map[string]any
		for len(kr) > 0 {
			g, ok1 := kr.u16()
			ke, ok2 := kr.vec16()
			if !ok1 || !ok2 {
				break
			}
			ch.KeyShareGroups = append(ch.KeyShareGroups, g)
			out = append(out, map[string]any{"group": g, "name": GroupName(g), "key_length": len(ke)})
		}
		return out
	case 45:
		v, _ := r.vec8()
		ch.PSKModes = append([]uint8(nil), v...)
		var names []string
		for _, m := range v {
			n, ok := pskModeNames[m]
			if !ok {
				n = strconv.Itoa(int(m))
			}
			names = append(names, n)
		}
		return names
	case 27:
		v, _ := r.vec8()
		ch.CertCompression = u16s(v)
		return named(ch.CertCompression, func(x uint16) string { return lookup(certCompressionNames, x) })
	case 28:
		if v, ok := r.u16(); ok {
			ch.RecordSizeLimit = int(v)
			return ch.RecordSizeLimit
		}
	case 34:
		v, _ := r.vec16()
		ch.DelegatedCredSigs = u16s(v)
		return named(ch.DelegatedCredSigs, SigAlgName)
	case 65037:
		ch.HasECH = true
		if t, ok := r.u8(); ok {
			m := map[string]any{"type": map[uint8]string{0: "outer", 1: "inner"}[t]}
			if t == 0 {
				kdf, _ := r.u16()
				aead, _ := r.u16()
				cfg, _ := r.u8()
				enc, _ := r.vec16()
				payload, _ := r.vec16()
				m["kdf_id"], m["aead_id"], m["config_id"] = kdf, aead, cfg
				m["enc_length"], m["payload_length"] = len(enc), len(payload)
			}
			ch.ECH = m
			return m
		}
	case 41:
		ch.HasPSK = true
		if ids, ok := r.vec16(); ok {
			ir := reader(ids)
			for len(ir) > 0 {
				if _, ok := ir.vec16(); !ok {
					break
				}
				ir.bytes(4)
				ch.PSKIdentities++
			}
		}
		return map[string]any{"identities": ch.PSKIdentities}
	case 35:
		ch.SessionTicketLen = len(data)
		return map[string]any{"ticket_length": len(data)}
	case 5:
		if t, ok := r.u8(); ok {
			return map[string]any{"status_type": t}
		}
	case 1:
		if len(data) == 1 {
			return map[string]any{"max_fragment_length": map[byte]int{1: 512, 2: 1024, 3: 2048, 4: 4096}[data[0]]}
		}
	case 57:
		ch.QUICParams = parseQUICParams(data)
		return ch.QUICParams
	case 42:
		ch.HasEarlyData = true
	case 21:
		ch.PaddingLen = len(data)
	}
	return nil
}

// Fingerprint is the JSON friendly fingerprint report for a ClientHello.
type Fingerprint struct {
	JA3         string `json:"ja3"`
	JA3Hash     string `json:"ja3_hash"`
	JA3N        string `json:"ja3n"`
	JA3NHash    string `json:"ja3n_hash"`
	JA4         string `json:"ja4"`
	JA4R        string `json:"ja4_r"`
	JA4O        string `json:"ja4_o"`
	JA4RO       string `json:"ja4_ro"`
	Peetprint   string `json:"peetprint"`
	PeetHash    string `json:"peetprint_hash"`
	ClientHello struct {
		RecordVersion       string         `json:"record_version"`
		LegacyVersion       string         `json:"legacy_version"`
		SupportedVersions   []string       `json:"supported_versions,omitempty"`
		ServerName          string         `json:"server_name,omitempty"`
		ALPN                []string       `json:"alpn,omitempty"`
		ALPS                []string       `json:"alps,omitempty"`
		SessionIDLength     int            `json:"session_id_length"`
		CipherSuites        []NamedValue   `json:"cipher_suites"`
		CompressionMethods  []uint8        `json:"compression_methods"`
		Extensions          []Extension    `json:"extensions"`
		SupportedGroups     []NamedValue   `json:"supported_groups,omitempty"`
		KeyShareGroups      []NamedValue   `json:"key_share_groups,omitempty"`
		SignatureAlgorithms []NamedValue   `json:"signature_algorithms,omitempty"`
		ECPointFormats      []uint8        `json:"ec_point_formats,omitempty"`
		CertCompression     []NamedValue   `json:"cert_compression,omitempty"`
		PSKModes            []uint8        `json:"psk_key_exchange_modes,omitempty"`
		RecordSizeLimit     int            `json:"record_size_limit,omitempty"`
		GREASE              bool           `json:"uses_grease"`
		ECH                 bool           `json:"encrypted_client_hello"`
		PSK                 bool           `json:"pre_shared_key"`
		EarlyData           bool           `json:"early_data"`
		PaddingLength       int            `json:"padding_length,omitempty"`
		HandshakeLength     int            `json:"handshake_length"`
		ExtensionOrder      []uint16       `json:"extension_order"`
		ExtensionNames      []string       `json:"extension_order_names"`
		ClientRandom        string         `json:"client_random"`
		SessionID           string         `json:"session_id,omitempty"`
		SessionTicketLength int            `json:"session_ticket_length,omitempty"`
		PSKIdentities       int            `json:"psk_identities,omitempty"`
		ECHDetails          map[string]any `json:"ech,omitempty"`
		DelegatedCredSigs   []NamedValue   `json:"delegated_credential_sigalgs,omitempty"`
		SigAlgsCert         []NamedValue   `json:"signature_algorithms_cert,omitempty"`
		QUICTransportParams []QUICParam    `json:"quic_transport_parameters,omitempty"`
		RawHex              string         `json:"raw_hex"`
	} `json:"client_hello"`
}

// NamedValue pairs a numeric code point with its name.
type NamedValue struct {
	ID   uint16 `json:"id"`
	Hex  string `json:"hex"`
	Name string `json:"name"`
}

func named(vs []uint16, f func(uint16) string) []NamedValue {
	out := make([]NamedValue, 0, len(vs))
	for _, v := range vs {
		out = append(out, NamedValue{ID: v, Hex: fmt.Sprintf("0x%04x", v), Name: f(v)})
	}
	return out
}

// Fingerprint computes all fingerprints for the ClientHello. quic selects the
// JA4 transport prefix ('q' instead of 't').
func (ch *ClientHello) Fingerprint(quic bool) *Fingerprint {
	f := &Fingerprint{}
	f.JA3 = ch.ja3(false)
	f.JA3Hash = md5hex(f.JA3)
	f.JA3N = ch.ja3(true)
	f.JA3NHash = md5hex(f.JA3N)
	f.JA4, f.JA4R = ch.ja4(quic, false)
	f.JA4O, f.JA4RO = ch.ja4(quic, true)
	f.Peetprint = ch.peetprint()
	f.PeetHash = md5hex(f.Peetprint)

	c := &f.ClientHello
	c.RecordVersion = VersionName(ch.RecordVersion)
	c.LegacyVersion = VersionName(ch.Version)
	for _, v := range ch.SupportedVersions {
		c.SupportedVersions = append(c.SupportedVersions, VersionName(v))
	}
	c.ServerName = ch.ServerName
	c.ALPN = ch.ALPN
	c.ALPS = ch.ALPS
	c.SessionIDLength = len(ch.SessionID)
	c.CipherSuites = named(ch.CipherSuites, CipherName)
	c.CompressionMethods = ch.CompressionMethods
	c.Extensions = ch.Extensions
	c.SupportedGroups = named(ch.SupportedGroups, GroupName)
	c.KeyShareGroups = named(ch.KeyShareGroups, GroupName)
	c.SignatureAlgorithms = named(ch.SignatureAlgorithms, SigAlgName)
	c.ECPointFormats = ch.ECPointFormats
	c.CertCompression = named(ch.CertCompression, func(x uint16) string { return lookup(certCompressionNames, x) })
	c.PSKModes = ch.PSKModes
	c.RecordSizeLimit = ch.RecordSizeLimit
	c.ECH = ch.HasECH
	c.PSK = ch.HasPSK
	c.EarlyData = ch.HasEarlyData
	c.PaddingLength = ch.PaddingLen
	c.HandshakeLength = ch.RawLength
	c.ClientRandom = hex.EncodeToString(ch.Random)
	c.SessionID = hex.EncodeToString(ch.SessionID)
	c.SessionTicketLength = ch.SessionTicketLen
	c.PSKIdentities = ch.PSKIdentities
	c.ECHDetails = ch.ECH
	if len(ch.DelegatedCredSigs) > 0 {
		c.DelegatedCredSigs = named(ch.DelegatedCredSigs, SigAlgName)
	}
	if len(ch.SigAlgsCert) > 0 {
		c.SigAlgsCert = named(ch.SigAlgsCert, SigAlgName)
	}
	c.QUICTransportParams = ch.QUICParams
	c.RawHex = hex.EncodeToString(ch.Raw)
	for _, e := range ch.Extensions {
		c.ExtensionNames = append(c.ExtensionNames, e.Name)
		c.ExtensionOrder = append(c.ExtensionOrder, e.ID)
		if IsGREASE(e.ID) {
			c.GREASE = true
		}
	}
	for _, v := range ch.CipherSuites {
		if IsGREASE(v) {
			c.GREASE = true
		}
	}
	return f
}

func (ch *ClientHello) ja3(sortExt bool) string {
	exts := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		if !IsGREASE(e.ID) {
			exts = append(exts, e.ID)
		}
	}
	if sortExt {
		sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	}
	pf := make([]string, len(ch.ECPointFormats))
	for i, v := range ch.ECPointFormats {
		pf[i] = strconv.Itoa(int(v))
	}
	return strings.Join([]string{
		strconv.Itoa(int(ch.Version)),
		joinDec(noGREASE(ch.CipherSuites)),
		joinDec(exts),
		joinDec(noGREASE(ch.SupportedGroups)),
		strings.Join(pf, "-"),
	}, ",")
}

func (ch *ClientHello) ja4(quic, original bool) (hashed, raw string) {
	proto := "t"
	if quic {
		proto = "q"
	}
	ver := ch.Version
	if sv := noGREASE(ch.SupportedVersions); len(sv) > 0 {
		ver = 0
		for _, v := range sv {
			if v > ver && v < 0xfe00 {
				ver = v
			}
		}
		if ver == 0 {
			ver = sv[0]
		}
	}
	vs := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}[ver]
	if vs == "" {
		vs = "00"
	}
	sni := "i"
	if ch.ServerName != "" {
		sni = "d"
	}
	ciphers := noGREASE(ch.CipherSuites)
	var exts []uint16
	for _, e := range ch.Extensions {
		if !IsGREASE(e.ID) {
			exts = append(exts, e.ID)
		}
	}
	alpn := "00"
	if len(ch.ALPN) > 0 && len(ch.ALPN[0]) > 0 {
		a := ch.ALPN[0]
		if isAlnum(a[0]) && isAlnum(a[len(a)-1]) {
			alpn = string(a[0]) + string(a[len(a)-1])
		} else {
			h := hex.EncodeToString([]byte(a))
			alpn = string(h[0]) + string(h[len(h)-1])
		}
	}
	a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, vs, sni, min(len(ciphers), 99), min(len(exts), 99), alpn)

	cs := append([]uint16(nil), ciphers...)
	es := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if original || (e != 0x0000 && e != 0x0010) {
			es = append(es, e)
		}
	}
	if !original {
		sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
		sort.Slice(es, func(i, j int) bool { return es[i] < es[j] })
	}
	b := joinHex(cs)
	c := joinHex(es)
	if sa := noGREASE(ch.SignatureAlgorithms); len(sa) > 0 {
		c += "_" + joinHex(sa)
	}
	raw = a + "_" + b + "_" + c
	hb, hc := "000000000000", "000000000000"
	if len(cs) > 0 {
		hb = sha12(b)
	}
	if len(es) > 0 {
		hc = sha12(c)
	}
	return a + "_" + hb + "_" + hc, raw
}

// peetprint follows the tls.peet.ws style:
// versions|alpn|groups|sigalgs|psk_modes|cert_compression|ciphers|sorted_extensions
func (ch *ClientHello) peetprint() string {
	g := func(vs []uint16) string {
		parts := make([]string, len(vs))
		for i, v := range vs {
			if IsGREASE(v) {
				parts[i] = "GREASE"
			} else {
				parts[i] = strconv.Itoa(int(v))
			}
		}
		return strings.Join(parts, "-")
	}
	psk := make([]string, len(ch.PSKModes))
	for i, v := range ch.PSKModes {
		psk[i] = strconv.Itoa(int(v))
	}
	var exts []uint16
	for _, e := range ch.Extensions {
		if !IsGREASE(e.ID) {
			exts = append(exts, e.ID)
		}
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	hasGrease := false
	for _, e := range ch.Extensions {
		if IsGREASE(e.ID) {
			hasGrease = true
		}
	}
	extStr := joinDec(exts)
	if hasGrease {
		extStr = "GREASE-" + extStr
	}
	return strings.Join([]string{
		g(ch.SupportedVersions),
		strings.Join(ch.ALPN, ","),
		g(ch.SupportedGroups),
		g(ch.SignatureAlgorithms),
		strings.Join(psk, "-"),
		g(ch.CertCompression),
		g(ch.CipherSuites),
		extStr,
	}, "|")
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func noGREASE(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinDec(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinHex(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func sha12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func u16s(b []byte) []uint16 {
	out := make([]uint16, len(b)/2)
	for i := range out {
		out[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	return out
}

func protoList(b []byte) []string {
	var out []string
	r := reader(b)
	for len(r) > 0 {
		p, ok := r.vec8()
		if !ok {
			break
		}
		out = append(out, string(p))
	}
	return out
}

type reader []byte

func (r *reader) u8() (uint8, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	v := (*r)[0]
	*r = (*r)[1:]
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := uint16((*r)[0])<<8 | uint16((*r)[1])
	*r = (*r)[2:]
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if len(*r) < n {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *reader) vec8() ([]byte, bool) {
	n, ok := r.u8()
	if !ok {
		return nil, false
	}
	return r.bytes(int(n))
}

func (r *reader) vec16() ([]byte, bool) {
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	return r.bytes(int(n))
}

// Complete reports whether raw holds the whole ClientHello without parsing
// it (it only walks record headers), so it is cheap to call on every read.
func Complete(raw []byte) bool {
	var head [4]byte
	got, total := 0, 0
	for p := raw; len(p) >= 5; {
		n := int(p[3])<<8 | int(p[4])
		if p[0] != 0x16 {
			return true // not a handshake: let Parse report the error
		}
		if len(p) < 5+n {
			return false
		}
		for i := 0; i < n && got < 4; i++ {
			head[got] = p[5+i]
			got++
		}
		total += n
		if got == 4 && total >= 4+(int(head[1])<<16|int(head[2])<<8|int(head[3])) {
			return true
		}
		p = p[5+n:]
	}
	return false
}

// ClientHellos returns every plaintext ClientHello in raw: normally one, two
// after a TLS 1.3 HelloRetryRequest (the second is sent in reply to the
// server's HRR, with a new key share). Parsing stops at encrypted records.
func ClientHellos(raw []byte) []*ClientHello {
	var out []*ClientHello
	var hs []byte
	for p := raw; len(p) >= 5; {
		typ, n := p[0], int(p[3])<<8|int(p[4])
		if len(p) < 5+n {
			break
		}
		body := p[5 : 5+n]
		p = p[5+n:]
		switch typ {
		case 0x14: // change_cipher_spec (middlebox compatibility)
			continue
		case 0x16:
			hs = append(hs, body...)
		default:
			return out
		}
		for len(hs) >= 4 {
			need := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if len(hs) < need {
				break
			}
			if hs[0] == 0x01 {
				if ch, err := ParseHandshake(hs[:need]); err == nil {
					out = append(out, ch)
				}
			}
			hs = hs[need:]
		}
	}
	return out
}
