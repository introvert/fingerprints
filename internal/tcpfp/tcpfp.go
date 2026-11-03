// Package tcpfp captures TCP/IP level fingerprints: the client's SYN packet
// (TTL, window, options order, MSS, window scale → JA4T and a p0f-style OS
// guess) via a raw AF_PACKET socket, and the kernel's TCP_INFO for an
// accepted connection (RTT, MSS, negotiated options).
package tcpfp

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SYN describes the first packet of a client connection as seen on the wire.
type SYN struct {
	CapturedAt   time.Time `json:"captured_at"`
	IPVersion    int       `json:"ip_version"`
	TTL          int       `json:"ttl"`
	InitialTTL   int       `json:"initial_ttl_guess"`
	Hops         int       `json:"hops_guess"`
	IPTotalLen   int       `json:"ip_total_length"`
	IPID         int       `json:"ip_id,omitempty"`
	DontFragment bool      `json:"dont_fragment"`
	TOS          int       `json:"tos"`
	ECN          string    `json:"ecn"`
	FlowLabel    int       `json:"ipv6_flow_label,omitempty"`
	Window       int       `json:"window_size"`
	Options      []string  `json:"options"`
	OptionKinds  []int     `json:"option_kinds"`
	MSS          int       `json:"mss,omitempty"`
	WindowScale  int       `json:"window_scale"`
	SACKPermit   bool      `json:"sack_permitted"`
	Timestamp    bool      `json:"timestamps"`
	TSVal        uint32    `json:"tsval,omitempty"`
	TCPFlags     string    `json:"tcp_flags"`
	ECNSetup     bool      `json:"ecn_setup"`
	JA4T         string    `json:"ja4t"`
	P0fLike      string    `json:"p0f_signature"`
	OSGuess      string    `json:"os_guess"`
	MTUGuess     int       `json:"mtu_guess,omitempty"`
	LinkGuess    string    `json:"link_guess,omitempty"`
}

var optNames = map[int]string{0: "EOL", 1: "NOP", 2: "MSS", 3: "WS", 4: "SACK_PERM", 5: "SACK", 8: "TS", 28: "UTO", 30: "MPTCP", 34: "TFO", 254: "EXP"}

func (s *SYN) finish() {
	switch {
	case s.TTL <= 32:
		s.InitialTTL = 32
	case s.TTL <= 64:
		s.InitialTTL = 64
	case s.TTL <= 128:
		s.InitialTTL = 128
	default:
		s.InitialTTL = 255
	}
	s.Hops = s.InitialTTL - s.TTL
	kinds := make([]string, len(s.OptionKinds))
	for i, k := range s.OptionKinds {
		kinds[i] = strconv.Itoa(k)
	}
	ws := "00"
	if s.WindowScale >= 0 {
		ws = strconv.Itoa(s.WindowScale)
	}
	mss := "00"
	if s.MSS > 0 {
		mss = strconv.Itoa(s.MSS)
	}
	s.JA4T = fmt.Sprintf("%d_%s_%s_%s", s.Window, strings.Join(kinds, "-"), mss, ws)
	// p0f v3 style: ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
	var lay []string
	for _, k := range s.OptionKinds {
		switch k {
		case 0:
			lay = append(lay, "eol")
		case 1:
			lay = append(lay, "nop")
		case 2:
			lay = append(lay, "mss")
		case 3:
			lay = append(lay, "ws")
		case 4:
			lay = append(lay, "sok")
		case 5:
			lay = append(lay, "sack")
		case 8:
			lay = append(lay, "ts")
		default:
			lay = append(lay, "?"+strconv.Itoa(k))
		}
	}
	var quirks []string
	if s.DontFragment {
		quirks = append(quirks, "df")
	}
	if s.IPVersion == 4 && s.IPID != 0 && s.DontFragment {
		quirks = append(quirks, "id+")
	}
	if s.ECNSetup {
		quirks = append(quirks, "ecn")
	}
	s.P0fLike = fmt.Sprintf("%d:%d:0:%d:%d,%d:%s:%s:0", s.IPVersion, s.InitialTTL, s.MSS, s.Window, max(s.WindowScale, 0), strings.Join(lay, ","), strings.Join(quirks, ","))
	s.OSGuess = guessOS(s)
	if s.MSS > 0 {
		hdr := 40
		if s.IPVersion == 6 {
			hdr = 60
		}
		s.MTUGuess = s.MSS + hdr
		s.LinkGuess = linkGuess(s.MTUGuess)
	}
}

func linkGuess(mtu int) string {
	switch {
	case mtu == 1500:
		return "Ethernet / standard"
	case mtu == 1492:
		return "PPPoE"
	case mtu == 1480:
		return "IPIP / 6in4 tunnel"
	case mtu == 1476:
		return "GRE"
	case mtu == 1420 || mtu == 1440:
		return "WireGuard or other VPN"
	case mtu >= 1400 && mtu < 1500:
		return "tunnel / VPN / mobile carrier"
	case mtu < 1400:
		return "VPN / tunnel (low MTU)"
	case mtu > 1500:
		return "jumbo frames / loopback"
	}
	return ""
}

func guessOS(s *SYN) string {
	lay := make([]string, len(s.OptionKinds))
	for i, k := range s.OptionKinds {
		lay[i] = strconv.Itoa(k)
	}
	l := strings.Join(lay, "-")
	switch {
	case s.InitialTTL == 128 && strings.HasPrefix(l, "2-1-3-1-1-4"):
		return "Windows"
	case s.InitialTTL == 128:
		return "Windows (likely)"
	case s.InitialTTL == 64 && l == "2-1-3-1-1-8-4-0-0":
		return "macOS / iOS"
	case s.InitialTTL == 64 && strings.HasPrefix(l, "2-4-8-1-3"):
		return "Linux / Android / ChromeOS"
	case s.InitialTTL == 64 && strings.HasPrefix(l, "2-1-3-1-1-8"):
		return "FreeBSD / macOS-like"
	case s.InitialTTL == 255:
		return "network device / Solaris"
	case s.InitialTTL == 64:
		return "Unix-like"
	}
	return "unknown"
}

// SynTable remembers recent SYNs by "ip:port" of the client.
type SynTable struct {
	mu sync.Mutex
	m  map[string]*SYN
}

// NewSynTable returns an empty table.
func NewSynTable() *SynTable { return &SynTable{m: map[string]*SYN{}} }

func (t *SynTable) put(key string, s *SYN) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[key] = s
	if len(t.m) > 50000 {
		cut := time.Now().Add(-2 * time.Minute)
		for k, v := range t.m {
			if v.CapturedAt.Before(cut) {
				delete(t.m, k)
			}
		}
		for k := range t.m { // SYN flood: drop arbitrary entries down to 90%
			if len(t.m) <= 45000 {
				break
			}
			delete(t.m, k)
		}
	}
}

// Lookup returns the SYN for remoteAddr ("ip:port") if one was captured.
func (t *SynTable) Lookup(remoteAddr string) *SYN {
	if t == nil {
		return nil
	}
	remoteAddr = strings.Replace(remoteAddr, "[::ffff:", "[", 1)
	if strings.HasPrefix(remoteAddr, "[") && strings.Count(remoteAddr, ".") == 3 {
		remoteAddr = strings.Replace(strings.TrimPrefix(remoteAddr, "["), "]", "", 1)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[remoteAddr]
}

// Info is a subset of the kernel's TCP_INFO for an established connection.
type Info struct {
	RTTMs          float64  `json:"rtt_ms"`
	RTTVarMs       float64  `json:"rtt_var_ms"`
	MinRTTMs       float64  `json:"min_rtt_ms,omitempty"`
	RcvMSS         int      `json:"rcv_mss_estimate"`
	SndMSS         int      `json:"send_mss"`
	AdvMSS         int      `json:"advertised_mss"`
	PMTU           int      `json:"path_mtu"`
	SndWScale      int      `json:"client_window_scale"`
	RcvWScale      int      `json:"server_window_scale"`
	Options        []string `json:"negotiated_options"`
	SndCwnd        int      `json:"send_cwnd"`
	Retransmits    int      `json:"retransmits"`
	TotalRetrans   int      `json:"total_retrans"`
	Reordering     int      `json:"reordering"`
	RcvSpace       int      `json:"rcv_space"`
	BytesReceived  uint64   `json:"bytes_received"`
	BytesAcked     uint64   `json:"bytes_acked"`
	SegsIn         int      `json:"segs_in"`
	SegsOut        int      `json:"segs_out"`
	DeliveryRate   uint64   `json:"delivery_rate_bps"`
	CongestionAlgo string   `json:"congestion_control,omitempty"`
}
