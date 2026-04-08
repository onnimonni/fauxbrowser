package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	nurl "net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/onnimonni/fauxbrowser/internal/ca"
)

// MITM handles HTTP CONNECT tunnels by terminating the curl-side TLS with
// an on-the-fly leaf cert and serving the decrypted stream via a shared
// http.Server whose Handler is the fauxbrowser ReverseProxy.
//
// One in-memory listener receives every accepted *tls.Conn from every
// CONNECT handler. The stdlib http.Server does h1/h2 negotiation, keep-
// alive, trailers, chunked encoding and WebSocket upgrades for us.
type MITM struct {
	cache     *ca.LeafCache
	transport *Transport

	listener *connPipe
	server   *http.Server

	wg sync.WaitGroup
}

// NewMITM wires up the listener + server. The caller is responsible for
// invoking Shutdown on exit.
func NewMITM(cache *ca.LeafCache, t *Transport) *MITM {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {},
		Transport: t,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("mitm upstream failed", "err", err, "url", safeURL(r))
			http.Error(w, "fauxbrowser upstream: "+err.Error(), http.StatusBadGateway)
		},
		FlushInterval: -1,
	}
	m := &MITM{
		cache:     cache,
		transport: t,
		listener:  newConnPipe(),
	}
	m.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// r.URL.Scheme/Host are unset for the decrypted side; fill them.
			u := &nurl.URL{
				Scheme:   "https",
				Host:     r.Host,
				Path:     r.URL.Path,
				RawQuery: r.URL.RawQuery,
			}
			setTarget(r, u)
			rp.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 15 * time.Second,
	}
	// Enable HTTP/2 on the server side so clients that negotiate h2 over
	// the MITM TLS stay on h2.
	_ = http2.ConfigureServer(m.server, &http2.Server{})

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		err := m.server.Serve(m.listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			slog.Error("mitm server exited", "err", err)
		}
	}()
	return m
}

// Shutdown stops the MITM server gracefully.
func (m *MITM) Shutdown(ctx context.Context) error {
	m.listener.Close()
	err := m.server.Shutdown(ctx)
	m.wg.Wait()
	return err
}

// HandleConnect hijacks the CONNECT request, negotiates TLS with the client
// using an on-the-fly leaf cert, and feeds the resulting *tls.Conn into the
// shared in-memory listener for http.Server.Serve to pick up.
func (m *MITM) HandleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		return
	}
	tlsConfig := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			h := host
			if hello.ServerName != "" {
				h = hello.ServerName
			}
			return m.cache.Get(h)
		},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	// Let the shared http.Server drive the TLS handshake lazily on first read.
	if err := m.listener.Push(tlsConn); err != nil {
		tlsConn.Close()
	}
}

// --- in-memory one-shot listener ---

type connPipe struct {
	ch     chan net.Conn
	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

func newConnPipe() *connPipe {
	return &connPipe{
		ch:   make(chan net.Conn),
		done: make(chan struct{}),
	}
}

func (p *connPipe) Push(c net.Conn) error {
	select {
	case p.ch <- c:
		return nil
	case <-p.done:
		return net.ErrClosed
	}
}

func (p *connPipe) Accept() (net.Conn, error) {
	select {
	case c := <-p.ch:
		return c, nil
	case <-p.done:
		return nil, net.ErrClosed
	}
}

func (p *connPipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	close(p.done)
	return nil
}

func (p *connPipe) Addr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "mitm" }
func (fakeAddr) String() string  { return "mitm://fauxbrowser" }
