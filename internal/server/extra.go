package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/introvert/fingerprints/internal/capture"
	"github.com/introvert/fingerprints/internal/store"
)

// navCache keeps recent document-request snapshots keyed by page nonce.
type navCache struct {
	mu sync.Mutex
	m  map[string]*NavigationInfo
}

func newNavCache() *navCache { return &navCache{m: map[string]*NavigationInfo{}} }

func (c *navCache) put(k string, v *NavigationInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= 20000 {
		cut := time.Now().Add(-30 * time.Minute)
		for k, v := range c.m {
			if v.At.Before(cut) {
				delete(c.m, k)
			}
		}
		for k := range c.m { // flood: drop arbitrary entries down to 90%
			if len(c.m) < 18000 {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[k] = v
}

func (c *navCache) get(k string) *NavigationInfo {
	if k == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[k]
}

// timingWriter adds a Server-Timing header with the handler duration.
type timingWriter struct {
	http.ResponseWriter
	start time.Time
	wrote bool
}

func (w *timingWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		w.Header().Set("Server-Timing", "app;dur="+strconv.FormatFloat(float64(time.Since(w.start).Microseconds())/1000, 'f', 3, 64))
		w.Header().Set("Timing-Allow-Origin", "*")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *timingWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *timingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController and HTTP/3 find the original writer.
func (w *timingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func wantsJSON(r *http.Request) bool {
	if strings.HasSuffix(r.PathValue("id"), ".json") || r.URL.Query().Get("format") != "" {
		return true
	}
	a := r.Header.Get("Accept")
	return strings.Contains(a, "application/json") && !strings.Contains(a, "text/html")
}

func (s *Server) handleSection(w http.ResponseWriter, r *http.Request) {
	s.section(w, r, r.PathValue("section"))
}

// section writes one top-level section of the current request's report.
func (s *Server) section(w http.ResponseWriter, r *http.Request, name string) {
	rep := s.serverReport(r)
	rep.Mode = "echo"
	rep.finalize()
	raw, _ := json.Marshal(rep)
	var m map[string]json.RawMessage
	json.Unmarshal(raw, &m)
	v, ok := m[name]
	if !ok || string(v) == "null" {
		s.writeErr(w, r, http.StatusNotFound, "section "+strconv.Quote(name)+" not available for this request")
		return
	}
	s.write(w, r, http.StatusOK, v)
}

// handlePing is a tiny endpoint for client-side latency and clock-skew probes.
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]any{"server_time_unix_ms": float64(time.Now().UnixMicro()) / 1000, "protocol": r.Proto}
	if ci := capture.FromContext(r.Context()); ci != nil {
		resp["connection_id"] = ci.ID
		resp["request_number_on_connection"] = ci.NextRequest()
		resp["protocol"] = ci.Protocol
		if ti := ci.TCPInfo(); ti != nil {
			resp["tcp_rtt_ms"] = ti.RTTMs
		}
		if h3, ok := ci.Extra.(*capture.H3Info); ok {
			if st := h3.Stats(); st != nil {
				resp["quic_rtt_ms"] = st.SmoothedRTTMS
			}
		}
	}
	s.write(w, r, http.StatusOK, resp)
}

// handleExport streams stored reports as NDJSON (one report per line).
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if !s.requireStore(w, r) {
		return
	}
	if !s.authorized(r) {
		s.writeErr(w, r, http.StatusUnauthorized, "admin token required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	list, err := s.store.List(r.Context(), store.Filter{Limit: limit})
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	for _, sm := range list {
		rec, err := s.store.Get(r.Context(), sm.ID)
		if err != nil {
			continue
		}
		w.Write(rec.Report)
		w.Write([]byte("\n"))
	}
}
