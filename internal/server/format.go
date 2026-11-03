package server

import (
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
	switch format(r) {
	case "text", "txt", "plain":
		raw, _ := json.Marshal(v)
		var m any
		json.Unmarshal(raw, &m)
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
			if json.Unmarshal(raw, &x) == nil {
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
	default:
		return fmt.Sprint(t)
	}
}
