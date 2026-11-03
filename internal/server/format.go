package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/introvert/fingerprints/internal/capture"
)

func connIsTLS(r *http.Request) bool {
	ci := capture.FromContext(r.Context())
	return ci != nil && ci.TLSState != nil
}

// format picks the output format: ?format=json|compact|text, else the Accept
// header (text/plain -> text), else pretty JSON.
func format(r *http.Request) string {
	if f := r.URL.Query().Get("format"); f != "" {
		return strings.ToLower(f)
	}
	if strings.HasPrefix(r.Header.Get("Accept"), "text/plain") {
		return "text"
	}
	return "json"
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if f := r.URL.Query().Get("fields"); f != "" && status < 400 {
		v = pickFields(v, strings.Split(f, ","))
	}
	switch format(r) {
	case "text", "txt", "plain":
		raw, _ := json.Marshal(v)
		var m any
		decodeNumber(raw, &m)
		flat := map[string]string{}
		flatten("", m, flat)
		keys := make([]string, 0, len(flat))
		for k := range flat {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		for _, k := range keys {
			fmt.Fprintf(w, "%s = %s\n", k, flat[k])
		}
	case "compact", "min":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	default:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if raw, ok := v.(json.RawMessage); ok {
			var x any
			if decodeNumber(raw, &x) == nil {
				v = x
			}
		}
		enc.Encode(v)
	}
}

func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.write(w, r, status, map[string]any{"error": msg, "status": status})
}

// flatten turns nested JSON into dotted paths.
func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 && prefix != "" {
			out[prefix] = "{}"
		}
		for k, x := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, x, out)
		}
	case []any:
		if len(t) == 0 {
			out[prefix] = "[]"
		}
		// short scalar arrays are kept on one line
		if len(t) > 0 && len(t) <= 64 && allScalar(t) {
			parts := make([]string, len(t))
			for i, x := range t {
				parts[i] = scalar(x)
			}
			out[prefix] = "[" + strings.Join(parts, ", ") + "]"
			return
		}
		for i, x := range t {
			flatten(prefix+"["+strconv.Itoa(i)+"]", x, out)
		}
	default:
		out[prefix] = scalar(t)
	}
}

func allScalar(xs []any) bool {
	for _, x := range xs {
		switch x.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func scalar(x any) string {
	switch t := x.(type) {
	case nil:
		return "null"
	case string:
		return strconv.Quote(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

// pickFields keeps only the given dotted paths (e.g. "tls.ja4,http2,summary").
func pickFields(v any, paths []string) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var src any
	if decodeNumber(raw, &src) != nil {
		return v
	}
	out := map[string]any{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		parts := strings.Split(p, ".")
		cur := src
		ok := true
		for _, k := range parts {
			m, isMap := cur.(map[string]any)
			if !isMap {
				ok = false
				break
			}
			if cur, ok = m[k]; !ok {
				break
			}
		}
		if !ok {
			continue
		}
		dst := out
		for _, k := range parts[:len(parts)-1] {
			next, _ := dst[k].(map[string]any)
			if next == nil {
				next = map[string]any{}
				dst[k] = next
			}
			dst = next
		}
		dst[parts[len(parts)-1]] = cur
	}
	return out
}

// decodeNumber decodes JSON keeping numbers exact (QUIC ids and GREASE
// values exceed 2^53 and would be rounded as float64).
func decodeNumber(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(v)
}
