// Package capture terminates TLS itself so that the raw ClientHello and the
// decrypted HTTP/1.x / HTTP/2 byte streams can be observed, then hands the
// connection to the standard Go HTTP servers. It also records TCP level data
// (SYN fingerprint, TCP_INFO) and connection timings.
package capture

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/introvert/fingerprints/internal/h2fp"
	"github.com/introvert/fingerprints/internal/httpfp"
	"github.com/introvert/fingerprints/internal/tcpfp"
	"github.com/introvert/fingerprints/internal/tlsfp"
)

// Timings are absolute timestamps of connection milestones (zero if unknown).
type Timings struct {
	Accepted         time.Time
	FirstByte        time.Time // first byte from client (ClientHello start)
	ClientHelloDone  time.Time // full ClientHello received
	ServerFlight     time.Time // first server write (ServerHello ...)
	ClientFinished   time.Time // first client bytes after the server flight
	HandshakeDone    time.Time
	FirstRequestByte time.Time // first application data byte
}

// ConnInfo describes one client connection.
type ConnInfo struct {
	ID            uint64
	RemoteAddr    string
	LocalAddr     string
	AcceptedAt    time.Time
	HandshakeTime time.Duration
	TLS           *tlsfp.Fingerprint
	TLSError      string
	TLSState      *tls.ConnectionState
	Protocol      string // "h2", "http/1.1", "http/1.1 (cleartext)", "h3"
	H2            *h2fp.Tracker
	H1            *httpfp.Tracker
	SYN           *tcpfp.SYN
	Timings       Timings
	// Extra holds transport specific data (e.g. the QUIC fingerprint).
	Extra    any
	raw      net.Conn
	mu       sync.Mutex
	requests atomic.Int64
}

// NextRequest returns the 1-based number of the current request on the connection.
func (c *ConnInfo) NextRequest() int64 { return c.requests.Add(1) }

// TCPInfo returns a fresh TCP_INFO snapshot (Linux only, nil otherwise).
func (c *ConnInfo) TCPInfo() *tcpfp.Info {
	if c.raw == nil {
		return nil
	}
	return tcpfp.GetInfo(c.raw)
}

// Snapshot returns a copy of the timings.
func (c *ConnInfo) Snapshot() Timings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Timings
}

type ctxKey struct{}

// FromContext returns the ConnInfo stored for a request.
func FromContext(ctx context.Context) *ConnInfo {
	ci, _ := ctx.Value(ctxKey{}).(*ConnInfo)
	return ci
}

// WithConnInfo attaches ci to ctx (used by other transports such as HTTP/3).
func WithConnInfo(ctx context.Context, ci *ConnInfo) context.Context {
	return context.WithValue(ctx, ctxKey{}, ci)
}

var connSeq atomic.Uint64

// NewConnID returns a process-unique connection id.
func NewConnID() uint64 { return connSeq.Add(1) }

// recordConn records the first bytes read (the ClientHello), tees all bytes
// read into a sink and timestamps handshake milestones.
type recordConn struct {
	net.Conn
	mu        sync.Mutex
	recording bool
	rec       []byte
	limit     int
	sink      io.Writer
	state     func() tls.ConnectionState
	info      *ConnInfo
	tlsLayer  bool // raw (encrypted) side of a TLS connection
	wrote     bool
}

func (c *recordConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		now := time.Now()
		c.mu.Lock()
		if c.recording && len(c.rec) < c.limit {
			c.rec = append(c.rec, p[:min(n, c.limit-len(c.rec))]...)
		}
		sink, wrote, recording, rec := c.sink, c.wrote, c.recording, c.rec
		c.mu.Unlock()
		ci := c.info
		ci.mu.Lock()
		t := &ci.Timings
		if c.tlsLayer {
			if t.FirstByte.IsZero() {
				t.FirstByte = now
			}
			if recording && t.ClientHelloDone.IsZero() && tlsfp.Complete(rec) {
				t.ClientHelloDone = now
			}
			if wrote && t.ClientFinished.IsZero() {
				t.ClientFinished = now
			}
		} else if t.FirstRequestByte.IsZero() {
			t.FirstRequestByte = now
			if t.FirstByte.IsZero() {
				t.FirstByte = now
			}
		}
		ci.mu.Unlock()
		if sink != nil {
			func() {
				defer func() { recover() }() // observation must never break serving
				sink.Write(p[:n])
			}()
		}
	}
	return n, err
}

func (c *recordConn) Write(p []byte) (int, error) {
	if c.tlsLayer {
		c.mu.Lock()
		first := !c.wrote
		c.wrote = true
		c.mu.Unlock()
		if first {
			c.info.mu.Lock()
			c.info.Timings.ServerFlight = time.Now()
			c.info.mu.Unlock()
		}
	}
	return c.Conn.Write(p)
}

// ConnectionState lets net/http and x/net/http2 populate Request.TLS.
func (c *recordConn) ConnectionState() tls.ConnectionState {
	if c.state != nil {
		return c.state()
	}
	return tls.ConnectionState{}
}

// Server serves HTTP over TLS (with fingerprinting) and plain HTTP.
type Server struct {
	Handler   http.Handler
	TLSConfig *tls.Config
	Logger    *log.Logger
	// SYNs, when set, is consulted for the SYN fingerprint of new connections.
	SYNs *tcpfp.SynTable

	once sync.Once
	h1   *http.Server
	h2   *http2.Server
	h1Ch chan net.Conn
}

func (s *Server) init() {
	s.once.Do(func() {
		s.h1Ch = make(chan net.Conn, 64)
		s.h1 = &http.Server{
			Handler:           s.Handler,
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       120 * time.Second,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				if rc, ok := c.(*recordConn); ok {
					return context.WithValue(ctx, ctxKey{}, rc.info)
				}
				return ctx
			},
			ErrorLog: s.Logger,
		}
		s.h2 = &http2.Server{IdleTimeout: 120 * time.Second}
		go func() {
			if err := s.h1.Serve(&chanListener{ch: s.h1Ch, addr: dummyAddr("tls-h1")}); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logf("h1 server: %v", err)
			}
		}()
	})
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (s *Server) newInfo(raw net.Conn) *ConnInfo {
	info := &ConnInfo{ID: NewConnID(), RemoteAddr: raw.RemoteAddr().String(), LocalAddr: raw.LocalAddr().String(), AcceptedAt: time.Now(), raw: raw}
	info.Timings.Accepted = info.AcceptedAt
	info.SYN = s.SYNs.Lookup(info.RemoteAddr)
	return info
}

// ServeTLS accepts raw TCP connections on ln and performs the TLS handshake
// itself while capturing the ClientHello.
func (s *Server) ServeTLS(ln net.Listener) error {
	s.init()
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handleTLS(c)
	}
}

func (s *Server) handleTLS(raw net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.logf("capture: recovered panic for %s: %v", raw.RemoteAddr(), r)
			raw.Close()
		}
	}()
	info := s.newInfo(raw)
	rc := &recordConn{Conn: raw, recording: true, limit: 64 << 10, info: info, tlsLayer: true}
	tc := tls.Server(rc, s.TLSConfig)
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	err := tc.Handshake()
	now := time.Now()
	info.HandshakeTime = now.Sub(info.AcceptedAt)
	info.mu.Lock()
	info.Timings.HandshakeDone = now
	info.mu.Unlock()

	rc.mu.Lock()
	rc.recording = false
	recorded := rc.rec
	rc.rec = nil
	rc.mu.Unlock()
	if ch, perr := tlsfp.Parse(recorded); perr == nil {
		info.TLS = ch.Fingerprint(false)
	} else {
		info.TLSError = perr.Error()
	}
	if info.SYN == nil {
		info.SYN = s.SYNs.Lookup(info.RemoteAddr) // capture goroutine may lag slightly
	}
	if err != nil {
		raw.Close()
		return
	}
	raw.SetDeadline(time.Time{})
	st := tc.ConnectionState()
	info.TLSState = &st
	if st.NegotiatedProtocol == "acme-tls/1" {
		tc.Close()
		return
	}

	// Wrap the decrypted stream so HTTP bytes are observed too.
	dc := &recordConn{Conn: tc, info: info, state: tc.ConnectionState}
	if st.NegotiatedProtocol == "h2" {
		info.Protocol = "h2"
		info.H2 = h2fp.NewTracker()
		dc.sink = info.H2
		ctx := context.WithValue(context.Background(), ctxKey{}, info)
		s.h2.ServeConn(dc, &http2.ServeConnOpts{Context: ctx, Handler: s.Handler, BaseConfig: s.h1})
		return
	}
	info.Protocol = "http/1.1"
	info.H1 = httpfp.NewTracker()
	dc.sink = info.H1
	s.h1Ch <- dc
}

// ServePlain serves cleartext HTTP/1.x on ln, still capturing header order.
func (s *Server) ServePlain(ln net.Listener) error {
	s.init()
	return s.h1.Serve(&plainListener{Listener: ln, s: s})
}

type plainListener struct {
	net.Listener
	s *Server
}

func (l *plainListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	info := l.s.newInfo(c)
	info.Protocol = "http/1.1 (cleartext)"
	info.H1 = httpfp.NewTracker()
	return &recordConn{Conn: c, info: info, sink: info.H1}, nil
}

type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
}

func (l *chanListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }
