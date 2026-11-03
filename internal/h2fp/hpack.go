package h2fp

import "strings"

// HPACKRepr describes how a header field was encoded on the wire. Encoders
// differ (Chrome, Firefox, Safari, Go, curl/nghttp2, okhttp), so the
// representation sequence is itself a fingerprint.
type HPACKRepr struct {
	// Type: indexed | incremental | without_indexing | never_indexed
	Type         string `json:"type"`
	Index        uint64 `json:"index,omitempty"` // table index (field for indexed, name otherwise)
	NameHuffman  bool   `json:"name_huffman,omitempty"`
	ValueHuffman bool   `json:"value_huffman,omitempty"`
	Code         string `json:"code"`
}

func readInt(b []byte, prefix uint) (uint64, int, bool) {
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

func readStr(b []byte) (huff bool, n int, ok bool) {
	if len(b) == 0 {
		return false, 0, false
	}
	l, k, ok := readInt(b, 7)
	if !ok || uint64(len(b)-k) < l {
		return false, 0, false
	}
	return b[0]&0x80 != 0, k + int(l), true
}

// scanHPACK walks a header block and reports each field's representation
// plus any dynamic table size updates.
func scanHPACK(b []byte) (reps []HPACKRepr, sizeUpdates []uint64) {
	for len(b) > 0 {
		c := b[0]
		var r HPACKRepr
		var prefix uint
		switch {
		case c&0x80 != 0:
			idx, n, ok := readInt(b, 7)
			if !ok {
				return
			}
			b = b[n:]
			reps = append(reps, HPACKRepr{Type: "indexed", Index: idx, Code: "I"})
			continue
		case c&0xc0 == 0x40:
			r.Type, prefix, r.Code = "incremental", 6, "A"
		case c&0xe0 == 0x20:
			v, n, ok := readInt(b, 5)
			if !ok {
				return
			}
			sizeUpdates = append(sizeUpdates, v)
			b = b[n:]
			continue
		case c&0xf0 == 0x10:
			r.Type, prefix, r.Code = "never_indexed", 4, "N"
		default:
			r.Type, prefix, r.Code = "without_indexing", 4, "W"
		}
		idx, n, ok := readInt(b, prefix)
		if !ok {
			return
		}
		b = b[n:]
		r.Index = idx
		if idx == 0 {
			h, n, ok := readStr(b)
			if !ok {
				return
			}
			r.NameHuffman = h
			b = b[n:]
			r.Code += "n"
		} else {
			r.Code += "i"
		}
		h, n, ok := readStr(b)
		if !ok {
			return
		}
		r.ValueHuffman = h
		if h {
			r.Code += "*"
		}
		b = b[n:]
		reps = append(reps, r)
	}
	return
}

func reprString(reps []HPACKRepr) string {
	codes := make([]string, len(reps))
	for i, r := range reps {
		codes[i] = r.Code
	}
	return strings.Join(codes, ",")
}
