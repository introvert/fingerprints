// Package server exposes the fingerprinting HTTP API and web UI.
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/introvert/fingerprints/internal/store"
	"github.com/introvert/fingerprints/web"
)

// Config configures the HTTP server.
type Config struct {
	// PublicURL is the base used for permalinks (e.g. https://fp.example.com).
	// When empty it is derived from the request.
	PublicURL string
	// TrustProxy uses X-Forwarded-For / X-Real-IP / X-Forwarded-Proto.
	TrustProxy bool
	// AdminToken, when set, is required (Bearer) for listing, related lookups
	// and deletion. When empty, listing is open and deletion is disabled.
	AdminToken string
	// MaxBody limits the size of posted client data.
	MaxBody int64
	// ReadOnly disables storing new fingerprints.
	ReadOnly bool
	// AltSvc, when set, is sent as the Alt-Svc header to advertise HTTP/3
	// (e.g. `h3=":443"; ma=86400`).
	AltSvc string
}

// Server is the HTTP handler.
type Server struct {
	cfg   Config
	store *store.Store
	mux   *http.ServeMux
	nav   *navCache
}

// New builds the handler. st may be nil, which disables storage.
func New(cfg Config, st *store.Store) *Server {
	if cfg.MaxBody == 0 {
		cfg.MaxBody = 4 << 20
	}
	s := &Server{cfg: cfg, store: st, mux: http.NewServeMux(), nav: newNavCache()}
	static, _ := fs.Sub(web.FS, "static")
	fileServer := http.FileServerFS(static)

	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /f/{id}", s.handleIndex)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(fileServer)))
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })

	// Server side (TLS / HTTP2 / headers) only. Works for curl & friends.
	for _, p := range []string{"GET /api/server", "GET /tls", "GET /json"} {
		s.mux.HandleFunc(p, s.handleServerOnly)
	}
	// Single sections of the server-side report.
	s.mux.HandleFunc("GET /api/server/{section}", s.handleSection)
	for path, section := range map[string]string{
		"/api/tls": "tls", "/api/tcp": "tcp", "/api/http2": "http2", "/api/http3": "http3",
		"/api/headers": "http", "/api/timing": "timing", "/api/hashes": "hashes", "/api/analysis": "analysis",
	} {
		sec := section
		s.mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) { s.section(w, r, sec) })
	}
	s.mux.HandleFunc("GET /api/ping", s.handlePing)
	s.mux.HandleFunc("GET /api/export", s.handleExport)
	s.mux.HandleFunc("GET /api/fingerprint", s.handleFingerprint)
	s.mux.HandleFunc("POST /api/fingerprint", s.handleFingerprint)

	s.mux.HandleFunc("GET /api/fingerprints", s.handleList)
	s.mux.HandleFunc("GET /api/fingerprints/{id}", s.handleGet)
	s.mux.HandleFunc("GET /api/fingerprints/{id}/related", s.handleRelated)
	s.mux.HandleFunc("DELETE /api/fingerprints/{id}", s.handleDelete)
	s.mux.HandleFunc("GET /api/compare", s.handleCompare)
	s.mux.HandleFunc("GET /api/info", s.handleInfo)
	return s
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

// Accept-CH asks Chromium browsers for high entropy client hints.
const acceptCH = "Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, " +
	"Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64, " +
	"Sec-CH-UA-Form-Factors, Sec-CH-Prefers-Color-Scheme, Sec-CH-Prefers-Reduced-Motion, " +
	"Sec-CH-Prefers-Reduced-Transparency, Sec-CH-Device-Memory, Sec-CH-DPR, Sec-CH-Viewport-Width, " +
	"Sec-CH-Viewport-Height, Device-Memory, DPR, Viewport-Width, Downlink, ECT, RTT, Save-Data"

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w = &timingWriter{ResponseWriter: w, start: start}
	if s.cfg.AltSvc != "" {
		w.Header().Set("Alt-Svc", s.cfg.AltSvc)
	}
	w.Header().Set("Accept-CH", acceptCH)
	w.Header().Set("Permissions-Policy", "ch-ua-arch=*, ch-ua-bitness=*, ch-ua-full-version-list=*, ch-ua-model=*, ch-ua-platform-version=*, ch-ua-wow64=*, ch-ua-form-factors=*")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// /f/{id} serves JSON to API clients.
	if id := r.PathValue("id"); id != "" && wantsJSON(r) {
		s.handleGet(w, r)
		return
	}
	b, err := fs.ReadFile(web.FS, "static/index.html")
	if err != nil {
		http.Error(w, "missing index", 500)
		return
	}
	// Remember the document request so the submitted report can include it.
	nav := s.serverReport(r)
	nonce := store.NewID() + store.NewID()
	ni := &NavigationInfo{HTTP: nav.HTTP, ConnectionID: nav.Network.ConnectionID, Protocol: nav.Network.ApplicationProtocol, At: time.Now().UTC()}
	if nav.TLS != nil && nav.TLS.Fingerprint != nil {
		ni.JA4 = nav.TLS.JA4
	}
	s.nav.put(nonce, ni)
	b = bytes.Replace(b, []byte("{{NONCE}}"), []byte(nonce), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Critical-CH", "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model")
	w.Write(b)
}

// --- fingerprint endpoints ---

type clientPayload struct {
	Label     string                     `json:"label"`
	Nonce     string                     `json:"nonce"`
	Client    *ClientData                `json:"client"`
	Libraries map[string]json.RawMessage `json:"libraries"`
}

func (s *Server) handleServerOnly(w http.ResponseWriter, r *http.Request) {
	rep := s.serverReport(r)
	rep.Mode = "echo"
	rep.finalize()
	s.write(w, r, http.StatusOK, rep)
}

// handleFingerprint: ?mode=echo (default) returns the report, ?mode=store
// also persists it and returns its id and permalink.
func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "echo"
	}
	if mode != "echo" && mode != "store" {
		s.writeErr(w, r, http.StatusBadRequest, "mode must be echo or store")
		return
	}
	rep := s.serverReport(r)
	rep.Mode = mode
	rep.Label = r.URL.Query().Get("label")
	if r.Method == http.MethodPost {
		var p clientPayload
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBody))
		if err != nil {
			s.writeErr(w, r, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &p); err != nil {
				s.writeErr(w, r, http.StatusBadRequest, "invalid JSON: "+err.Error())
				return
			}
		}
		rep.Client = p.Client
		rep.Libraries = p.Libraries
		if ni := s.nav.get(p.Nonce); ni != nil {
			cp := *ni
			cp.SameConnection = ni.ConnectionID != 0 && ni.ConnectionID == rep.Network.ConnectionID
			rep.Navigation = &cp
			rep.Timing.NavigationToSubmitMS = float64(time.Since(ni.At).Microseconds()) / 1000
		}
		if p.Label != "" {
			rep.Label = p.Label
		}
	}
	if len(rep.Label) > 200 {
		rep.Label = rep.Label[:200]
	}
	rep.finalize()

	if mode == "store" {
		if s.store == nil || s.cfg.ReadOnly {
			s.writeErr(w, r, http.StatusServiceUnavailable, "storage is disabled on this server")
			return
		}
		rep.ID = store.NewID()
		s.links(r, rep)
		raw, _ := json.Marshal(rep)
		rec := &store.Record{Summary: s.summaryOf(rep), Report: raw}
		if err := s.store.Insert(r.Context(), rec); err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "store: "+err.Error())
			return
		}
		w.Header().Set("Location", rep.APIURL)
		s.write(w, r, http.StatusCreated, rep)
		return
	}
	s.write(w, r, http.StatusOK, rep)
}

func (s *Server) summaryOf(rep *Report) store.Summary {
	sm := store.Summary{
		ID: rep.ID, CreatedAt: rep.CreatedAt, IP: rep.Network.IP, UserAgent: rep.HTTP.UserAgent, Label: rep.Label,
		JA3: rep.Hashes["ja3"], JA4: rep.Hashes["ja4"], HTTP2: rep.Hashes["http2_akamai"],
		BrowserHash: rep.Hashes["browser"], CombinedHash: rep.Hashes["combined"],
	}
	sm.VisitorID = rep.libraryString("fingerprintjs", "visitorId")
	return sm
}

func (s *Server) baseURL(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return strings.TrimRight(s.cfg.PublicURL, "/")
	}
	scheme := "http"
	if r.TLS != nil || connIsTLS(r) {
		scheme = "https"
	}
	if s.cfg.TrustProxy {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = p
		}
	}
	return scheme + "://" + r.Host
}

func (s *Server) links(r *http.Request, rep *Report) {
	base := s.baseURL(r)
	rep.Permalink = base + "/f/" + rep.ID
	rep.APIURL = base + "/api/fingerprints/" + rep.ID
}

// --- history endpoints ---

func (s *Server) requireStore(w http.ResponseWriter, r *http.Request) bool {
	if s.store == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "storage is disabled on this server")
		return false
	}
	return true
}

func (s *Server) authorized(r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		return true
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.AdminToken)) == 1
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireStore(w, r) {
		return
	}
	rec, err := s.store.Get(r.Context(), strings.TrimSuffix(r.PathValue("id"), ".json"))
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, http.StatusNotFound, "fingerprint not found")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
	w.Header().Set("Vary", "Accept")
	s.write(w, r, http.StatusOK, json.RawMessage(rec.Report))
}

func (s *Server) handleRelated(w http.ResponseWriter, r *http.Request) {
	if !s.requireStore(w, r) {
		return
	}
	if !s.authorized(r) {
		s.writeErr(w, r, http.StatusUnauthorized, "admin token required")
		return
	}
	rec, err := s.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, http.StatusNotFound, "fingerprint not found")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 25
	}
	rel, err := s.store.Related(r.Context(), &rec.Summary, limit)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	s.write(w, r, http.StatusOK, map[string]any{"id": rec.ID, "related": rel})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	if !s.requireStore(w, r) {
		return
	}
	if !s.authorized(r) {
		s.writeErr(w, r, http.StatusUnauthorized, "admin token required")
		return
	}
	q := r.URL.Query()
	f := store.Filter{
		JA3: q.Get("ja3"), JA4: q.Get("ja4"), HTTP2: q.Get("http2"), BrowserHash: q.Get("browser_hash"),
		CombinedHash: q.Get("combined_hash"), VisitorID: q.Get("visitor_id"), IP: q.Get("ip"), Label: q.Get("label"),
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	if b := q.Get("before"); b != "" {
		if t, err := time.Parse(time.RFC3339Nano, b); err == nil {
			f.Before = t
		}
	}
	list, err := s.store.List(r.Context(), f)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	base := s.baseURL(r)
	type item struct {
		store.Summary
		Permalink string `json:"permalink"`
	}
	items := make([]item, len(list))
	for i, sm := range list {
		items[i] = item{sm, base + "/f/" + sm.ID}
	}
	resp := map[string]any{"count": len(items), "items": items}
	if len(list) > 0 && len(list) == max(f.Limit, 1) {
		resp["next_before"] = list[len(list)-1].CreatedAt.Format(time.RFC3339Nano)
	}
	s.write(w, r, http.StatusOK, resp)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireStore(w, r) {
		return
	}
	if s.cfg.AdminToken == "" || !s.authorized(r) {
		s.writeErr(w, r, http.StatusUnauthorized, "admin token required")
		return
	}
	err := s.store.Delete(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, http.StatusNotFound, "fingerprint not found")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCompare diffs two stored fingerprints (?a=id&b=id). "b" may be
// omitted to compare against the current request's server-side fingerprint.
func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	if !s.requireStore(w, r) {
		return
	}
	load := func(ctx context.Context, id string) (map[string]any, error) {
		rec, err := s.store.Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		var m map[string]any
		return m, json.Unmarshal(rec.Report, &m)
	}
	a, err := load(r.Context(), r.URL.Query().Get("a"))
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, err.Error())
		return
	}
	var b map[string]any
	if id := r.URL.Query().Get("b"); id != "" {
		if b, err = load(r.Context(), id); err != nil {
			s.writeErr(w, r, http.StatusNotFound, err.Error())
			return
		}
	} else {
		rep := s.serverReport(r)
		rep.finalize()
		raw, _ := json.Marshal(rep)
		json.Unmarshal(raw, &b)
	}
	// identity, volatile and derived fields are not interesting in a diff
	skip := []string{"id", "permalink", "api_url", "created_at", "mode", "label", "network.", "analysis.", "summary.", "client.duration_ms", "client.components.timing."}
	fa, fb := map[string]string{}, map[string]string{}
	flatten("", a, fa)
	flatten("", b, fb)
	type diff struct {
		Path string `json:"path"`
		A    string `json:"a"`
		B    string `json:"b"`
	}
	var diffs []diff
	keys := map[string]bool{}
	for k := range fa {
		keys[k] = true
	}
	for k := range fb {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	equal := 0
outer:
	for _, k := range sorted {
		for _, p := range skip {
			if k == p || strings.HasPrefix(k, p) {
				continue outer
			}
		}
		if strings.HasSuffix(k, "duration_ms") || strings.HasSuffix(k, ".hash") && strings.HasPrefix(k, "client.components.") {
			continue
		}
		if fa[k] == fb[k] {
			equal++
			continue
		}
		diffs = append(diffs, diff{k, fa[k], fb[k]})
	}
	hashCmp := map[string]bool{}
	ha, _ := a["hashes"].(map[string]any)
	hb, _ := b["hashes"].(map[string]any)
	for k, v := range ha {
		hashCmp[k] = fmt.Sprint(v) == fmt.Sprint(hb[k])
	}
	s.write(w, r, http.StatusOK, map[string]any{
		"a": a["id"], "b": b["id"], "hashes_equal": hashCmp,
		"equal_fields": equal, "different_fields": len(diffs), "differences": diffs,
	})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]any{
		"storage":        s.store != nil && !s.cfg.ReadOnly,
		"history_open":   s.cfg.AdminToken == "",
		"tls_terminated": connIsTLS(r),
		"libraries":      []string{"fingerprintjs@5.3.0", "thumbmarkjs@1.12.0"},
	}
	if s.store != nil {
		n, _ := s.store.Count(r.Context())
		info["stored"] = n
	}
	s.write(w, r, http.StatusOK, info)
}
