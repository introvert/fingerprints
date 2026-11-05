package capture

import (
	"context"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/introvert/fingerprints/internal/quicfp"
)

// H3Info is attached to ConnInfo.Extra for HTTP/3 connections.
type H3Info struct {
	QUIC  *quicfp.Fingerprint
	Table *quicfp.Table
	Addr  string
	conn  *quic.Conn
	mu    sync.Mutex
	set   *H3Settings
}

// H3Settings are the client's HTTP/3 SETTINGS (order is not exposed by quic-go).
type H3Settings struct {
	EnableDatagrams       bool              `json:"h3_datagram"`
	EnableExtendedConnect bool              `json:"enable_connect_protocol"`
	Other                 map[string]uint64 `json:"other,omitempty"`
}

// QUICStats are RTT estimates from the QUIC stack.
type QUICStats struct {
	MinRTTMS      float64 `json:"min_rtt_ms"`
	SmoothedRTTMS float64 `json:"smoothed_rtt_ms"`
	LatestRTTMS   float64 `json:"latest_rtt_ms"`
	RTTVarMS      float64 `json:"rtt_var_ms"`
}

// Stats returns current RTT statistics.
func (h *H3Info) Stats() *QUICStats {
	if h == nil || h.conn == nil {
		return nil
	}
	st := h.conn.ConnectionStats()
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	return &QUICStats{MinRTTMS: ms(st.MinRTT), SmoothedRTTMS: ms(st.SmoothedRTT), LatestRTTMS: ms(st.LatestRTT), RTTVarMS: ms(st.MeanDeviation)}
}

// Settings returns the client's HTTP/3 SETTINGS if received.
func (h *H3Info) Settings() *H3Settings {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.set
}

var h3SettingNames = map[uint64]string{0x1: "QPACK_MAX_TABLE_CAPACITY", 0x6: "MAX_FIELD_SECTION_SIZE", 0x7: "QPACK_BLOCKED_STREAMS",
	0x8: "ENABLE_CONNECT_PROTOCOL", 0x33: "H3_DATAGRAM", 0x2b603742: "ENABLE_WEBTRANSPORT", 0xc671706a: "WEBTRANSPORT_MAX_SESSIONS"}

// ServeH3 serves HTTP/3 on pc, fingerprinting each connection's Initial
// packets. The returned Table can be queried by client address.
func (s *Server) ServeH3(pc net.PacketConn) error {
	s.init()
	table := quicfp.NewTable()
	tr := &quic.Transport{Conn: &quicfp.TeeConn{PacketConn: pc, Table: table}, ConnectionIDLength: table.CIDLen}
	base := s.TLSConfig.Clone()
	// Our own session secrets let the tap decrypt the client's 1-RTT packets
	// (HTTP/3 SETTINGS order, QPACK field order and encodings).
	base.KeyLogWriter = table.KeyLogWriter()
	tlsConf := http3.ConfigureTLSConfig(base)
	ln, err := tr.Listen(tlsConf, &quic.Config{MaxIdleTimeout: 60 * time.Second})
	if err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ci := FromContext(r.Context()); ci != nil {
			if h, ok := ci.Extra.(*H3Info); ok && h.Settings() == nil {
				if sg, ok := w.(http3.Settingser); ok {
					select {
					case <-sg.ReceivedSettings():
						st := sg.Settings()
						hs := &H3Settings{EnableDatagrams: st.EnableDatagrams, EnableExtendedConnect: st.EnableExtendedConnect}
						if len(st.Other) > 0 {
							hs.Other = map[string]uint64{}
							keys := make([]uint64, 0, len(st.Other))
							for k := range st.Other {
								keys = append(keys, k)
							}
							sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
							for _, k := range keys {
								n := h3SettingNames[k]
								if k >= 0x21 && (k-0x21)%0x1f == 0 {
									n = "GREASE_0x" + formatHex(k)
								}
								if n == "" {
									n = "0x" + formatHex(k)
								}
								hs.Other[n] = st.Other[k]
							}
						}
						h.mu.Lock()
						h.set = hs
						h.mu.Unlock()
					case <-time.After(150 * time.Millisecond):
					}
				}
			}
		}
		s.Handler.ServeHTTP(w, r)
	})
	srv := &http3.Server{
		Handler: handler,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			addr := c.RemoteAddr().String()
			ci := &ConnInfo{ID: NewConnID(), RemoteAddr: addr, LocalAddr: c.LocalAddr().String(), AcceptedAt: time.Now(), Protocol: "h3"}
			h := &H3Info{QUIC: table.Lookup(addr), conn: c, Table: table, Addr: addr}
			if h.QUIC != nil {
				ci.TLS = h.QUIC.TLS
				ci.AcceptedAt = h.QUIC.FirstSeen
				ci.Timings.FirstByte = h.QUIC.FirstSeen
			}
			ci.Timings.Accepted = ci.AcceptedAt
			ci.Timings.HandshakeDone = time.Now()
			ci.HandshakeTime = ci.Timings.HandshakeDone.Sub(ci.AcceptedAt)
			st := c.ConnectionState().TLS
			ci.TLSState = &st
			ci.Extra = h
			return WithConnInfo(ctx, ci)
		},
	}
	return srv.ServeListener(ln)
}

func formatHex(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{digits[v&0xf]}, b...)
		v >>= 4
	}
	return string(b)
}
