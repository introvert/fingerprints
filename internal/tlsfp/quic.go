package tlsfp

import (
	"encoding/hex"
	"fmt"
)

var quicParamNames = map[uint64]string{
	0x00: "original_destination_connection_id", 0x01: "max_idle_timeout", 0x02: "stateless_reset_token",
	0x03: "max_udp_payload_size", 0x04: "initial_max_data", 0x05: "initial_max_stream_data_bidi_local",
	0x06: "initial_max_stream_data_bidi_remote", 0x07: "initial_max_stream_data_uni", 0x08: "initial_max_streams_bidi",
	0x09: "initial_max_streams_uni", 0x0a: "ack_delay_exponent", 0x0b: "max_ack_delay", 0x0c: "disable_active_migration",
	0x0d: "preferred_address", 0x0e: "active_connection_id_limit", 0x0f: "initial_source_connection_id",
	0x10: "retry_source_connection_id", 0x11: "version_information", 0x20: "max_datagram_frame_size",
	0x2ab2: "grease_quic_bit", 0x3127: "initial_rtt", 0x3128: "google_connection_options",
	0x4752: "google_version", 0xff04de1b: "min_ack_delay", 0x0f739bbc1b666d05: "enable_multipath",
	0xff73db: "version_information_draft", 0x173e: "discard",
}

// varint-valued QUIC parameters
var quicVarintParams = map[uint64]bool{0x01: true, 0x03: true, 0x04: true, 0x05: true, 0x06: true, 0x07: true,
	0x08: true, 0x09: true, 0x0a: true, 0x0b: true, 0x0e: true, 0x20: true, 0x3127: true, 0xff04de1b: true}

// ReadVarint decodes a QUIC variable-length integer.
func ReadVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

func parseQUICParams(b []byte) []QUICParam {
	var out []QUICParam
	for len(b) > 0 {
		id, n, ok := ReadVarint(b)
		if !ok {
			break
		}
		b = b[n:]
		l, n, ok := ReadVarint(b)
		if !ok || uint64(len(b)-n) < l {
			break
		}
		val := b[n : n+int(l)]
		b = b[n+int(l):]
		p := QUICParam{ID: id, Name: quicParamNames[id]}
		if id >= 27 && (id-27)%31 == 0 {
			p.GREASE, p.Name = true, "GREASE"
		}
		if p.Name == "" {
			p.Name = fmt.Sprintf("unknown(0x%x)", id)
		}
		switch {
		case p.GREASE:
			p.Value = len(val)
		case quicVarintParams[id]:
			if v, _, ok := ReadVarint(val); ok {
				p.Value = v
			}
		case len(val) == 0:
			p.Value = true
		default:
			p.Value = hex.EncodeToString(val)
		}
		out = append(out, p)
	}
	return out
}
