// Package capture terminates TLS itself so that the raw ClientHello and the
// decrypted HTTP/1.x / HTTP/2 byte streams can be observed, then hands the
// connection to the standard Go HTTP servers.
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
	"github.com/introvert/fingerprints/internal/tlsfp"
)

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
	Protocol      string // "h2", "http/1.1", "http/1.1 (cleartext)"
	H2            *h2fp.Tracker
	H1            *httpfp.Tracker
	requests      atomic.Int64
}

// RequestIndex returns the 1-based number of requests served on this connection
// so far (including the current one).
func (c *ConnInfo) NextRequest() int64 { return c.requests.Add(1) }

type ctxKey struct{}

// FromContext returns the ConnInfo stored for a request.
func FromContext(ctx context.Context) *ConnInfo {
	ci, _ := ctx.Value(ctxKey{}).(*ConnInfo)
	return ci
}

var connSeq atomic.Uint64

// recordConn records the first bytes read (the ClientHello) and optionally
// tees all bytes read into a sink.
type recordConn struct {
	net.Conn
	mu        sync.Mutex
	recording bool
	rec       []byte
	limit     int
	sink      io.Writer
	state     func() tls.ConnectionState
	info      *ConnInfo
}

func (c *recordConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if c.recording && len(c.rec) < c.limit {
			c.rec = append(c.rec, p[:min(n, c.limit-len(c.rec))]...)
		}
		sink := c.sink
		c.mu.Unlock()
		if sink != nil {
			sink.Write(p[:n])
		}
	}
	return n, err
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

	once  sync.Once
	h1    *http.Server
	h2    *http2.Server
	h1Ch  chan net.Conn
	errCh chan error
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
	info := &ConnInfo{ID: connSeq.Add(1), RemoteAddr: raw.RemoteAddr().String(), LocalAddr: raw.LocalAddr().String(), AcceptedAt: time.Now()}
	rc := &recordConn{Conn: raw, recording: true, limit: 64 << 10, info: info}
	tc := tls.Server(rc, s.TLSConfig)
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	err := tc.Handshake()
	info.HandshakeTime = time.Since(info.AcceptedAt)

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
	return s.h1.Serve(&plainListener{Listener: ln})
}

type plainListener struct{ net.Listener }

func (l *plainListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	info := &ConnInfo{ID: connSeq.Add(1), RemoteAddr: c.RemoteAddr().String(), LocalAddr: c.LocalAddr().String(), AcceptedAt: time.Now(), Protocol: "http/1.1 (cleartext)", H1: httpfp.NewTracker()}
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
