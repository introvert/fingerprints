//go:build linux

package tcpfp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// StartSYNCapture opens an AF_PACKET socket (needs CAP_NET_RAW) and records
// SYN packets destined to any of ports.
func StartSYNCapture(ports []int) (*SynTable, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("tcpfp: raw socket (needs root/CAP_NET_RAW): %w", err)
	}
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	t := NewSynTable()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if sa, ok := from.(*unix.SockaddrLinklayer); ok && sa.Pkttype == unix.PACKET_OUTGOING {
				continue
			}
			if s, key := parseSYN(buf[:n], want); s != nil {
				t.put(key, s)
			}
		}
	}()
	return t, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func parseSYN(p []byte, ports map[int]bool) (*SYN, string) {
	if len(p) < 20 {
		return nil, ""
	}
	s := &SYN{CapturedAt: time.Now(), WindowScale: -1}
	var tcp []byte
	var src net.IP
	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&0x0f) * 4
		if p[9] != 6 || len(p) < ihl+20 {
			return nil, ""
		}
		s.IPVersion = 4
		s.TOS = int(p[1])
		s.IPTotalLen = int(binary.BigEndian.Uint16(p[2:]))
		s.IPID = int(binary.BigEndian.Uint16(p[4:]))
		s.DontFragment = p[6]&0x40 != 0
		s.TTL = int(p[8])
		src = net.IP(p[12:16])
		tcp = p[ihl:]
	case 6:
		if len(p) < 60 || p[6] != 6 { // extension headers not handled
			return nil, ""
		}
		s.IPVersion = 6
		s.TOS = int(p[0]&0x0f)<<4 | int(p[1]>>4)
		s.FlowLabel = int(binary.BigEndian.Uint32(p[0:4]) & 0xfffff)
		s.IPTotalLen = int(binary.BigEndian.Uint16(p[4:])) + 40
		s.TTL = int(p[7])
		src = net.IP(p[8:24])
		tcp = p[40:]
	default:
		return nil, ""
	}
	flags := tcp[13]
	if flags&0x02 == 0 || flags&0x10 != 0 { // SYN without ACK
		return nil, ""
	}
	dport := int(binary.BigEndian.Uint16(tcp[2:]))
	if !ports[dport] {
		return nil, ""
	}
	sport := int(binary.BigEndian.Uint16(tcp[0:]))
	s.ECN = [...]string{"Not-ECT", "ECT(1)", "ECT(0)", "CE"}[s.TOS&3]
	s.ECNSetup = flags&0xc0 == 0xc0
	names := []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
	for i, n := range names {
		if flags&(1<<i) != 0 {
			if s.TCPFlags != "" {
				s.TCPFlags += ","
			}
			s.TCPFlags += n
		}
	}
	s.Window = int(binary.BigEndian.Uint16(tcp[14:]))
	off := int(tcp[12]>>4) * 4
	if off > len(tcp) {
		return nil, ""
	}
	opts := tcp[20:off]
	for i := 0; i < len(opts); {
		k := int(opts[i])
		s.OptionKinds = append(s.OptionKinds, k)
		name := optNames[k]
		if name == "" {
			name = fmt.Sprintf("OPT%d", k)
		}
		if k == 0 || k == 1 {
			s.Options = append(s.Options, name)
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		d := opts[i+2 : i+l]
		switch k {
		case 2:
			if len(d) == 2 {
				s.MSS = int(binary.BigEndian.Uint16(d))
				name = fmt.Sprintf("MSS=%d", s.MSS)
			}
		case 3:
			if len(d) == 1 {
				s.WindowScale = int(d[0])
				name = fmt.Sprintf("WS=%d", s.WindowScale)
			}
		case 4:
			s.SACKPermit = true
		case 8:
			s.Timestamp = true
			if len(d) >= 4 {
				s.TSVal = binary.BigEndian.Uint32(d)
			}
		}
		s.Options = append(s.Options, name)
		i += l
	}
	s.finish()
	return s, net.JoinHostPort(src.String(), fmt.Sprint(sport))
}

// GetInfo reads TCP_INFO from a TCP connection.
func GetInfo(c net.Conn) *Info {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return nil
	}
	var ti *unix.TCPInfo
	var cc string
	rc.Control(func(fd uintptr) {
		ti, _ = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		cc, _ = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	})
	if ti == nil {
		return nil
	}
	in := &Info{
		RTTMs: float64(ti.Rtt) / 1000, RTTVarMs: float64(ti.Rttvar) / 1000, MinRTTMs: float64(ti.Min_rtt) / 1000,
		RcvMSS: int(ti.Rcv_mss), SndMSS: int(ti.Snd_mss), AdvMSS: int(ti.Advmss), PMTU: int(ti.Pmtu),
		// snd_wscale/rcv_wscale are a bitfield byte at offset 6 that the Go
		// struct only exposes as padding.
		SndWScale: int((*[8]byte)(unsafe.Pointer(ti))[6] & 0x0f), RcvWScale: int((*[8]byte)(unsafe.Pointer(ti))[6] >> 4),
		SndCwnd: int(ti.Snd_cwnd), Retransmits: int(ti.Retransmits), TotalRetrans: int(ti.Total_retrans),
		Reordering: int(ti.Reordering), RcvSpace: int(ti.Rcv_space), BytesReceived: ti.Bytes_received,
		BytesAcked: ti.Bytes_acked, SegsIn: int(ti.Segs_in), SegsOut: int(ti.Segs_out), DeliveryRate: ti.Delivery_rate,
		CongestionAlgo: trimNul(cc),
	}
	if ti.Options&0x1 != 0 {
		in.Options = append(in.Options, "timestamps")
	}
	if ti.Options&0x2 != 0 {
		in.Options = append(in.Options, "sack")
	}
	if ti.Options&0x4 != 0 {
		in.Options = append(in.Options, "window_scaling")
	}
	if ti.Options&0x8 != 0 {
		in.Options = append(in.Options, "ecn")
	}
	if ti.Options&0x20 != 0 {
		in.Options = append(in.Options, "syn_data(tfo)")
	}
	return in
}

func trimNul(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return s[:i]
		}
	}
	return s
}
