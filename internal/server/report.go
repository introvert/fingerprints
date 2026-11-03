package server

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/introvert/fingerprints/internal/capture"
	"github.com/introvert/fingerprints/internal/h2fp"
	"github.com/introvert/fingerprints/internal/httpfp"
	"github.com/introvert/fingerprints/internal/quicfp"
	"github.com/introvert/fingerprints/internal/tcpfp"
	"github.com/introvert/fingerprints/internal/tlsfp"
)

// Report is the complete fingerprint document returned to clients and stored.
type Report struct {
	ID        string    `json:"id,omitempty"`
	Permalink string    `json:"permalink,omitempty"`
	APIURL    string    `json:"api_url,omitempty"`
	Mode      string    `json:"mode"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"created_at"`

	Summary  map[string]any    `json:"summary"`
	Hashes   map[string]string `json:"hashes"`
	Analysis *Analysis         `json:"analysis"`

	Network *NetworkInfo      `json:"network"`
	TLS     *TLSInfo          `json:"tls"`
	HTTP2   *h2fp.Fingerprint `json:"http2"`
	HTTP3   *HTTP3Info        `json:"http3,omitempty"`
	HTTP    *HTTPInfo         `json:"http"`
	TCP     *TCPReport        `json:"tcp,omitempty"`
	Timing  *TimingReport     `json:"timing"`
	// Navigation is the server-side view of the request that loaded the
	// collector page (document request headers differ from fetch()).
	Navigation *NavigationInfo `json:"navigation,omitempty"`

	// Client-side (JavaScript) data. Absent for server-only fingerprints.
	Client    *ClientData                `json:"client,omitempty"`
	Libraries map[string]json.RawMessage `json:"libraries,omitempty"`
}

// NetworkInfo describes the transport connection.
type NetworkInfo struct {
	IP                  string   `json:"ip"`
	Port                string   `json:"port"`
	RemoteAddr          string   `json:"remote_addr"`
	ForwardedFor        []string `json:"forwarded_for,omitempty"`
	ConnectionID        uint64   `json:"connection_id,omitempty"`
	RequestOnConn       int64    `json:"request_number_on_connection,omitempty"`
	ConnectionAgeMS     int64    `json:"connection_age_ms,omitempty"`
	HandshakeMS         float64  `json:"tls_handshake_ms,omitempty"`
	ApplicationProtocol string   `json:"protocol"`
}

// TLSInfo combines the ClientHello fingerprint and the negotiated parameters.
type TLSInfo struct {
	*tlsfp.Fingerprint
	Error      string         `json:"error,omitempty"`
	Negotiated *TLSNegotiated `json:"negotiated,omitempty"`
	Note       string         `json:"note,omitempty"`
}

// TLSNegotiated holds the parameters chosen by the server.
type TLSNegotiated struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	ALPN        string `json:"alpn"`
	ServerName  string `json:"server_name"`
	Resumed     bool   `json:"resumed"`
	ECHAccepted bool   `json:"ech_accepted"`
	CurveID     string `json:"key_exchange_group,omitempty"`
}

// HTTPInfo is the request level HTTP fingerprint.
type HTTPInfo struct {
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Version      string            `json:"version"`
	Host         string            `json:"host"`
	UserAgent    string            `json:"user_agent"`
	HeaderOrder  []string          `json:"header_order"`
	Headers      []httpfp.Header   `json:"headers"`
	HeaderSource string            `json:"header_source"`
	JA4H         string            `json:"ja4h"`
	JA4HRaw      string            `json:"ja4h_r"`
	ClientHints  map[string]string `json:"client_hints,omitempty"`
	H2Priority   *h2fp.Priority    `json:"h2_headers_priority,omitempty"`
	H2Flags      []string          `json:"h2_headers_flags,omitempty"`
	HPACKCodes   string            `json:"hpack_codes,omitempty"`
	HeaderCount  int               `json:"header_count"`
	HeaderBytes  int               `json:"header_bytes"`
	PseudoOrder  string            `json:"pseudo_header_order,omitempty"`
	Casing       string            `json:"header_name_casing"`
}

// TCPReport holds TCP/IP level data.
type TCPReport struct {
	SYN  *tcpfp.SYN  `json:"syn,omitempty"`
	Info *tcpfp.Info `json:"info,omitempty"`
	Note string      `json:"note,omitempty"`
}

// HTTP3Info holds the QUIC / HTTP/3 fingerprint.
type HTTP3Info struct {
	QUIC     *quicfp.Fingerprint `json:"quic,omitempty"`
	Settings *capture.H3Settings `json:"settings,omitempty"`
	Stats    *capture.QUICStats  `json:"rtt,omitempty"`
	Note     string              `json:"note,omitempty"`
}

// TimingReport contains connection and request timings in milliseconds.
type TimingReport struct {
	ServerTimeMS              float64 `json:"server_time_unix_ms"`
	ConnectionAgeMS           float64 `json:"connection_age_ms"`
	AcceptToFirstByteMS       float64 `json:"accept_to_first_byte_ms,omitempty"`
	ClientHelloTransferMS     float64 `json:"client_hello_transfer_ms,omitempty"`
	ServerHandshakeMS         float64 `json:"server_handshake_processing_ms,omitempty"`
	TLSRoundTripMS            float64 `json:"tls_round_trip_ms,omitempty"`
	HandshakeTotalMS          float64 `json:"handshake_total_ms,omitempty"`
	HandshakeToFirstRequestMS float64 `json:"handshake_to_first_request_ms,omitempty"`
	H2PrefaceToHeadersMS      float64 `json:"h2_preface_to_first_headers_ms,omitempty"`
	RequestOnConnection       int64   `json:"request_number_on_connection,omitempty"`
	TCPRTTMS                  float64 `json:"tcp_rtt_ms,omitempty"`
	TCPRTTVarMS               float64 `json:"tcp_rtt_var_ms,omitempty"`
	TCPMinRTTMS               float64 `json:"tcp_min_rtt_ms,omitempty"`
	QUICSmoothedRTTMS         float64 `json:"quic_smoothed_rtt_ms,omitempty"`
	QUICMinRTTMS              float64 `json:"quic_min_rtt_ms,omitempty"`
	NavigationToSubmitMS      float64 `json:"navigation_to_submit_ms,omitempty"`
}

// NavigationInfo is captured when the collector page itself was requested.
type NavigationInfo struct {
	HTTP           *HTTPInfo `json:"http"`
	ConnectionID   uint64    `json:"connection_id,omitempty"`
	SameConnection bool      `json:"same_connection_as_submit"`
	Protocol       string    `json:"protocol"`
	JA4            string    `json:"ja4,omitempty"`
	At             time.Time `json:"at"`
}

// ClientData is what the browser collector posts.
type ClientData struct {
	Version    string                      `json:"version,omitempty"`
	DurationMS float64                     `json:"duration_ms,omitempty"`
	Components map[string]*ClientComponent `json:"components"`
}

// ClientComponent is one JS signal.
type ClientComponent struct {
	Value    json.RawMessage `json:"value,omitempty"`
	Error    string          `json:"error,omitempty"`
	Duration float64         `json:"duration_ms,omitempty"`
	Hash     string          `json:"hash,omitempty"`
}

// volatileComponents change between visits of the same browser and are
// excluded from browser_hash.
var volatileComponents = map[string]bool{
	"battery": true, "connection": true, "window": true, "document": true, "timing": true,
	"storage": true, "webrtc": true, "performance": true, "gamepads": true, "mediaDevices": true,
	"permissions": true, "latency": true, "navigationTiming": true, "audioContext": true,
}

func clientIP(r *http.Request, trustProxy bool) (ip, port string, fwd []string) {
	ip, port, _ = net.SplitHostPort(r.RemoteAddr)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, p := range strings.Split(xff, ",") {
			fwd = append(fwd, strings.TrimSpace(p))
		}
	}
	if trustProxy {
		if len(fwd) > 0 && fwd[0] != "" {
			ip = fwd[0]
		} else if xr := r.Header.Get("X-Real-IP"); xr != "" {
			ip = xr
		}
	}
	return
}

var clientHintHeaders = []string{
	"Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform", "Sec-CH-UA-Platform-Version", "Sec-CH-UA-Arch",
	"Sec-CH-UA-Bitness", "Sec-CH-UA-Model", "Sec-CH-UA-Full-Version", "Sec-CH-UA-Full-Version-List",
	"Sec-CH-UA-WoW64", "Sec-CH-UA-Form-Factors", "Sec-CH-Prefers-Color-Scheme", "Sec-CH-Prefers-Reduced-Motion",
	"Sec-CH-Prefers-Reduced-Transparency", "Sec-CH-Device-Memory", "Sec-CH-DPR", "Sec-CH-Viewport-Width",
	"Sec-CH-Viewport-Height", "Device-Memory", "DPR", "Viewport-Width", "Downlink", "ECT", "RTT", "Save-Data",
	"Sec-GPC", "DNT",
}

func (s *Server) serverReport(r *http.Request) *Report {
	rep := &Report{CreatedAt: time.Now().UTC(), Hashes: map[string]string{}, Summary: map[string]any{}}
	rep.Timing = &TimingReport{ServerTimeMS: float64(time.Now().UnixMicro()) / 1000}
	ci := capture.FromContext(r.Context())

	ip, port, fwd := clientIP(r, s.cfg.TrustProxy)
	rep.Network = &NetworkInfo{IP: ip, Port: port, RemoteAddr: r.RemoteAddr, ForwardedFor: fwd, ApplicationProtocol: r.Proto}

	rep.HTTP = &HTTPInfo{Method: r.Method, Path: r.URL.RequestURI(), Version: r.Proto, Host: r.Host, UserAgent: r.UserAgent()}
	ver := map[int]string{1: "11", 2: "20", 3: "30"}[r.ProtoMajor]
	if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		ver = "10"
	}

	var headers []httpfp.Header
	if ci != nil {
		rep.Network.ConnectionID = ci.ID
		rep.Network.RequestOnConn = ci.NextRequest()
		rep.Network.ConnectionAgeMS = time.Since(ci.AcceptedAt).Milliseconds()
		rep.Network.ApplicationProtocol = ci.Protocol
		if ci.HandshakeTime > 0 && ci.TLSState != nil {
			rep.Network.HandshakeMS = float64(ci.HandshakeTime.Microseconds()) / 1000
		}
		if ci.TLS != nil || ci.TLSError != "" {
			rep.TLS = &TLSInfo{Fingerprint: ci.TLS, Error: ci.TLSError}
		}
		if ci.TLSState != nil {
			if rep.TLS == nil {
				rep.TLS = &TLSInfo{}
			}
			st := ci.TLSState
			rep.TLS.Negotiated = &TLSNegotiated{
				Version: tls.VersionName(st.Version), CipherSuite: tls.CipherSuiteName(st.CipherSuite),
				ALPN: st.NegotiatedProtocol, ServerName: st.ServerName, Resumed: st.DidResume, ECHAccepted: st.ECHAccepted,
			}
			if st.CurveID != 0 {
				rep.TLS.Negotiated.CurveID = tlsfp.GroupName(uint16(st.CurveID))
			}
		}
		if ci.H2 != nil {
			rep.HTTP2 = ci.H2.Fingerprint()
			if hb := ci.H2.RequestHeaders(r.Method, r.RequestURI); hb != nil {
				for _, h := range hb.Headers {
					hh := httpfp.Header{Name: h.Name, Value: h.Value}
					if h.HPACK != nil {
						hh.Encoding = h.HPACK
					}
					headers = append(headers, hh)
				}
				rep.HTTP.HeaderSource = "hpack (wire order)"
				rep.HTTP.H2Priority = hb.Priority
				rep.HTTP.H2Flags = hb.Flags
				rep.HTTP.HPACKCodes = hb.HPACKCodes
			}
		}
		if h3, ok := ci.Extra.(*capture.H3Info); ok {
			rep.HTTP3 = &HTTP3Info{QUIC: h3.QUIC, Settings: h3.Settings(), Stats: h3.Stats(),
				Note: "HTTP/3 header order is not available (QPACK is decoded inside quic-go)"}
		}
		s.fillTransport(rep, ci)
		if ci.H1 != nil {
			if req := ci.H1.Request(r.Method, r.RequestURI); req != nil {
				headers = req.Headers
				rep.HTTP.HeaderSource = "raw request (wire order)"
			}
		}
	}
	if rep.TLS == nil {
		rep.TLS = &TLSInfo{Note: "no TLS fingerprint: connection was not TLS terminated by this server (plain HTTP or behind a TLS-terminating proxy)"}
	}
	if headers == nil {
		rep.HTTP.HeaderSource = "go net/http (order NOT preserved)"
		keys := make([]string, 0, len(r.Header))
		for k := range r.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range r.Header[k] {
				headers = append(headers, httpfp.Header{Name: k, Value: v})
			}
		}
	}
	rep.HTTP.Headers = headers
	var pseudo []string
	lower, upper := 0, 0
	for _, h := range headers {
		rep.HTTP.HeaderOrder = append(rep.HTTP.HeaderOrder, h.Name)
		rep.HTTP.HeaderBytes += len(h.Name) + len(h.Value) + 4
		if strings.HasPrefix(h.Name, ":") {
			pseudo = append(pseudo, h.Name)
		} else if h.Name == strings.ToLower(h.Name) {
			lower++
		} else {
			upper++
		}
	}
	rep.HTTP.HeaderCount = len(headers)
	rep.HTTP.PseudoOrder = strings.Join(pseudo, ",")
	switch {
	case upper == 0:
		rep.HTTP.Casing = "lowercase"
	case lower == 0:
		rep.HTTP.Casing = "Canonical-Case"
	default:
		rep.HTTP.Casing = "mixed"
	}
	if strings.HasPrefix(rep.HTTP.HeaderSource, "go net/http") {
		// wire order unknown (HTTP/3 / unwrapped connection): an order-based
		// fingerprint would be misleading, so it is left empty.
		rep.HTTP.JA4H, rep.HTTP.JA4HRaw = "", "unavailable: header order not observable on this transport"
	} else {
		rep.HTTP.JA4H, rep.HTTP.JA4HRaw = httpfp.JA4H(r.Method, ver, headers)
	}
	for _, h := range clientHintHeaders {
		if v := r.Header.Get(h); v != "" {
			if rep.HTTP.ClientHints == nil {
				rep.HTTP.ClientHints = map[string]string{}
			}
			rep.HTTP.ClientHints[strings.ToLower(h)] = v
		}
	}
	return rep
}

// finalize computes hashes, summary and analysis.
func (rep *Report) finalize() {
	h := rep.Hashes
	if t := rep.TLS; t != nil && t.Fingerprint != nil {
		h["ja3"] = t.JA3Hash
		h["ja3n"] = t.JA3NHash
		h["ja4"] = t.JA4
		h["ja4_o"] = t.JA4O
		h["peetprint"] = t.PeetHash
	}
	if rep.HTTP2 != nil {
		h["http2_akamai"] = rep.HTTP2.AkamaiHash
		if rep.HTTP2.HPACKCodes != "" {
			h["hpack"] = sha(rep.HTTP2.HPACKCodes)[:16]
		}
	}
	if rep.TCP != nil && rep.TCP.SYN != nil {
		h["ja4t"] = rep.TCP.SYN.JA4T
		h["p0f"] = sha(rep.TCP.SYN.P0fLike)[:16]
	}
	if rep.HTTP3 != nil && rep.HTTP3.QUIC != nil {
		if rep.HTTP3.QUIC.TLS != nil {
			h["ja4_quic"] = rep.HTTP3.QUIC.TLS.JA4
		}
		h["quic"] = sha(rep.HTTP3.QUIC.QUICFingerprint)[:16]
	}
	if rep.Navigation != nil && rep.Navigation.HTTP != nil && rep.Navigation.HTTP.JA4H != "" {
		h["ja4h_navigation"] = rep.Navigation.HTTP.JA4H
	}
	if rep.HTTP != nil {
		if rep.HTTP.JA4H != "" {
			h["ja4h"] = rep.HTTP.JA4H
			h["header_order"] = sha(strings.Join(rep.HTTP.HeaderOrder, ","))[:16]
		}
	}
	if rep.Client != nil && len(rep.Client.Components) > 0 {
		names := make([]string, 0, len(rep.Client.Components))
		for k, c := range rep.Client.Components {
			if c == nil {
				continue
			}
			c.Hash = sha(string(canonical(c.Value)) + "|" + c.Error)[:16]
			names = append(names, k)
		}
		sort.Strings(names)
		var all, stable []string
		for _, n := range names {
			line := n + ":" + rep.Client.Components[n].Hash
			all = append(all, line)
			if !volatileComponents[n] {
				stable = append(stable, line)
			}
		}
		h["browser"] = sha(strings.Join(stable, ","))[:32]
		h["browser_all"] = sha(strings.Join(all, ","))[:32]
	}
	// combined = transport (TLS + HTTP/2) + stable browser hash
	var parts []string
	for _, k := range []string{"ja4", "http2_akamai", "browser"} {
		parts = append(parts, k+"="+h[k])
	}
	h["transport"] = sha(parts[0] + "|" + parts[1])[:32]
	h["combined"] = sha(strings.Join(parts, "|"))[:32]

	sm := rep.Summary
	sm["ip"] = rep.Network.IP
	sm["user_agent"] = rep.HTTP.UserAgent
	sm["protocol"] = rep.Network.ApplicationProtocol
	if t := rep.TLS; t != nil && t.Fingerprint != nil {
		sm["ja3_hash"] = t.JA3Hash
		sm["ja4"] = t.JA4
		sm["peetprint_hash"] = t.PeetHash
	}
	if t := rep.TLS; t != nil && t.Negotiated != nil {
		sm["tls_version"] = t.Negotiated.Version
	}
	if rep.HTTP2 != nil {
		sm["http2_akamai"] = rep.HTTP2.Akamai
	}
	if rep.HTTP.JA4H != "" {
		sm["ja4h"] = rep.HTTP.JA4H
	}
	if rep.TCP != nil && rep.TCP.SYN != nil {
		sm["ja4t"] = rep.TCP.SYN.JA4T
		sm["tcp_os_guess"] = rep.TCP.SYN.OSGuess
	}
	if rep.Timing != nil && rep.Timing.TCPRTTMS > 0 {
		sm["tcp_rtt_ms"] = rep.Timing.TCPRTTMS
	}
	if rep.HTTP3 != nil && rep.HTTP3.QUIC != nil && rep.HTTP3.QUIC.TLS != nil {
		sm["ja4_quic"] = rep.HTTP3.QUIC.TLS.JA4
	}
	if rep.Navigation != nil && rep.Navigation.HTTP != nil && rep.Navigation.HTTP.JA4H != "" {
		sm["ja4h_navigation"] = rep.Navigation.HTTP.JA4H
	}
	if _, ok := h["browser"]; ok {
		sm["browser_hash"] = h["browser"]
	}
	sm["combined_hash"] = h["combined"]
	if v := rep.libraryString("fingerprintjs", "visitorId"); v != "" {
		sm["fingerprintjs_visitor_id"] = v
	}
	if v := rep.libraryString("thumbmarkjs", "thumbmark"); v != "" {
		sm["thumbmark"] = v
	}
	rep.Analysis = analyze(rep)
	sm["suspicion_score"] = rep.Analysis.Score
}

func (rep *Report) libraryString(lib, key string) string {
	raw, ok := rep.Libraries[lib]
	if !ok {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// component decodes a client component value into v.
func (rep *Report) component(name string, v any) bool {
	if rep.Client == nil {
		return false
	}
	c, ok := rep.Client.Components[name]
	if !ok || c == nil || len(c.Value) == 0 {
		return false
	}
	return json.Unmarshal(c.Value, v) == nil
}

func canonical(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	b, _ := json.Marshal(v) // map keys are sorted by encoding/json
	return b
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func msBetween(a, b time.Time) float64 {
	if a.IsZero() || b.IsZero() || b.Before(a) {
		return 0
	}
	return float64(b.Sub(a).Microseconds()) / 1000
}

// fillTransport adds TCP and timing sections from the connection info.
func (s *Server) fillTransport(rep *Report, ci *capture.ConnInfo) {
	t := ci.Snapshot()
	now := time.Now()
	tm := rep.Timing
	tm.ConnectionAgeMS = msBetween(ci.AcceptedAt, now)
	tm.RequestOnConnection = rep.Network.RequestOnConn
	tm.AcceptToFirstByteMS = msBetween(t.Accepted, t.FirstByte)
	tm.ClientHelloTransferMS = msBetween(t.FirstByte, t.ClientHelloDone)
	tm.ServerHandshakeMS = msBetween(t.ClientHelloDone, t.ServerFlight)
	tm.TLSRoundTripMS = msBetween(t.ServerFlight, t.ClientFinished)
	tm.HandshakeTotalMS = msBetween(t.Accepted, t.HandshakeDone)
	tm.HandshakeToFirstRequestMS = msBetween(t.HandshakeDone, t.FirstRequestByte)
	if rep.HTTP2 != nil {
		tm.H2PrefaceToHeadersMS = rep.HTTP2.PrefaceToFirstHeadersMS
	}
	if ci.Protocol == "h3" {
		if rep.HTTP3 != nil && rep.HTTP3.Stats != nil {
			tm.QUICSmoothedRTTMS = rep.HTTP3.Stats.SmoothedRTTMS
			tm.QUICMinRTTMS = rep.HTTP3.Stats.MinRTTMS
		}
		return
	}
	tcp := &TCPReport{SYN: ci.SYN, Info: ci.TCPInfo()}
	if tcp.SYN == nil {
		tcp.Note = "SYN fingerprint unavailable (enable with -syn-capture; Linux, needs CAP_NET_RAW)"
	}
	if tcp.Info != nil {
		tm.TCPRTTMS, tm.TCPRTTVarMS, tm.TCPMinRTTMS = tcp.Info.RTTMs, tcp.Info.RTTVarMs, tcp.Info.MinRTTMs
	}
	if tcp.SYN != nil || tcp.Info != nil {
		rep.TCP = tcp
	}
}
