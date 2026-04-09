// Plaintext h2c listener for Elixir clients.
//
// We serve HTTP/1.1 AND HTTP/2 cleartext (h2c) on the same port via
// golang.org/x/net/http2/h2c, so Elixir's Mint can open a single TCP
// connection and multiplex many concurrent requests over it. There is
// no TLS on this side — traffic between the Elixir worker and
// fauxbrowser is plaintext on loopback by default.
//
// Request modes (in priority order):
//
//  1. X-Target-URL header → r.URL is rewritten to that absolute URL.
//  2. Absolute URI in the request line (classic forward-proxy style) →
//     r.URL is already absolute; reuse it.
//
// CONNECT is NOT supported. TLS MITM was removed in v0.5.
package proxy

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	nurl "net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Options for the top-level proxy handler.
type Options struct {
	TargetHeader string // e.g. "X-Target-URL"
	Transport    *Transport
}

// NewHandler builds the HTTP handler tree.
func NewHandler(opts Options) http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// Front door already set r.URL correctly; do nothing.
		},
		Transport: opts.Transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("upstream failed", "err", err, "url", safeURL(r))
			http.Error(w, "fauxbrowser upstream: "+err.Error(), http.StatusBadGateway)
		},
		FlushInterval: -1,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "fauxbrowser: CONNECT not supported (use X-Target-URL or absolute URI)",
				http.StatusNotImplemented)
			return
		}
		// X-Target-URL header mode.
		if t := r.Header.Get(opts.TargetHeader); t != "" {
			u, err := nurl.Parse(t)
			if err != nil || !u.IsAbs() {
				http.Error(w, "bad "+opts.TargetHeader, http.StatusBadRequest)
				return
			}
			setTarget(r, u)
			rp.ServeHTTP(w, r)
			return
		}
		// Classic forward-proxy: absolute URI in request line.
		if r.URL != nil && r.URL.IsAbs() {
			setTarget(r, r.URL)
			rp.ServeHTTP(w, r)
			return
		}
		http.Error(w, "fauxbrowser: set "+opts.TargetHeader+" or send an absolute-URI request line",
			http.StatusBadRequest)
	})
}

// WrapH2C wraps an http.Handler with h2c (HTTP/2 cleartext) upgrade
// support. The resulting handler speaks both HTTP/1.1 and h2 over
// plaintext TCP on the same listener.
func WrapH2C(h http.Handler) http.Handler {
	h2s := &http2.Server{
		// IdleTimeout covers both h1 keep-alive and h2 idle streams.
		IdleTimeout: 5 * time.Minute,
	}
	return h2c.NewHandler(h, h2s)
}

// setTarget rewrites r so ReverseProxy routes it upstream unchanged.
func setTarget(r *http.Request, u *nurl.URL) {
	r.URL = u
	r.Host = u.Host
	r.RequestURI = ""
}

func safeURL(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.String()
}

// HostOnly strips the port from a host:port string. Used by main.go.
func HostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
