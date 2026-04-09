// Plaintext h2c listener for Elixir clients.
//
// We serve HTTP/1.1 AND HTTP/2 cleartext (h2c) on the same port via
// golang.org/x/net/http2/h2c, so Elixir's Mint can open a single TCP
// connection and multiplex many concurrent requests over it. There is
// no TLS on this side — traffic between the worker and fauxbrowser is
// plaintext on loopback by default.
//
// Request modes (in priority order):
//
//  1. CONNECT host:port → opens a transparent TCP tunnel through the
//     WireGuard dialer. The client speaks TLS directly to the target;
//     fauxbrowser sees only encrypted bytes. Use this mode when you
//     want to point an HTTP_PROXY-aware client (Lightpanda, curl -x,
//     a browser) at fauxbrowser purely for VPN egress. NOTE: this
//     bypasses the chrome146 TLS fingerprint forging AND the rotator's
//     429-on-response heuristic. Per-host quarantine still applies at
//     dial time. HTTP/1.1 only — h2c CONNECT is not supported.
//  2. X-Target-URL header → r.URL is rewritten to that absolute URL.
//     Full feature path: TLS forging, header scrub, rotation, cookie
//     jar all active.
//  3. Absolute URI in the request line (classic forward-proxy style)
//     → r.URL is already absolute; reuse it. Same feature set as
//     X-Target-URL.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	nurl "net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/net/proxy"
)

// Options for the top-level proxy handler.
type Options struct {
	TargetHeader string // e.g. "X-Target-URL"
	Transport    *Transport
	// Dialer is the same proxy.ContextDialer that backs the Transport.
	// Used by the CONNECT handler to dial the upstream target. May be
	// nil — CONNECT requests will then return 501.
	Dialer proxy.ContextDialer
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
			handleConnect(w, r, opts.Dialer)
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

// handleConnect implements HTTP/1.1 CONNECT tunneling. It hijacks the
// client connection, dials the upstream via the provided dialer (which
// routes through the WireGuard tunnel + per-host quarantine gate), and
// then bidirectionally pipes raw bytes between the two.
//
// Caveats — read these before using:
//
//   - The client's own TLS stack speaks directly to the target. The
//     chrome146 TLS fingerprint forging that fauxbrowser provides for
//     X-Target-URL traffic is NOT in effect for CONNECT traffic. If
//     the target is behind a TLS-fingerprint-aware WAF (Cloudflare
//     IUAM, Akamai Bot Manager, DataDome) you will fail.
//   - Because the bytes inside the tunnel are encrypted, fauxbrowser
//     cannot see HTTP status codes, headers, or cookies. The rotator's
//     429/403/503 heuristic does NOT fire on CONNECT traffic. You can
//     still rotate manually via POST /rotate on the admin listener.
//   - The header scrub (X-Forwarded-For, Via, etc.) does NOT apply to
//     CONNECT traffic — those headers live inside the encrypted
//     stream and fauxbrowser never sees them. Make sure your client
//     doesn't set them.
//   - Per-host quarantine gates DO apply at dial time, so a host that
//     was quarantined by a recent X-Target-URL 429 will block this
//     CONNECT dial too until the quarantine lifts.
//   - HTTP/2 CONNECT is not supported. h2 strips Hijacker support.
func handleConnect(w http.ResponseWriter, r *http.Request, dialer proxy.ContextDialer) {
	if dialer == nil {
		http.Error(w, "fauxbrowser: CONNECT not configured (no Dialer)",
			http.StatusNotImplemented)
		return
	}
	target := normalizeConnectTarget(r.Host)
	if target == "" {
		http.Error(w, "fauxbrowser: CONNECT missing host", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "fauxbrowser: CONNECT requires HTTP/1.1 (h2 cannot hijack)",
			http.StatusNotImplemented)
		return
	}

	dialCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	upstream, err := dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		slog.Warn("CONNECT dial failed", "target", target, "err", err)
		http.Error(w, "fauxbrowser: CONNECT dial: "+err.Error(), http.StatusBadGateway)
		return
	}

	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		slog.Warn("CONNECT hijack failed", "err", err)
		return
	}

	// Tell the client we're tunneling. After this, the connection is
	// raw bytes both ways.
	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = upstream.Close()
		_ = clientConn.Close()
		return
	}
	if err := bufrw.Flush(); err != nil {
		_ = upstream.Close()
		_ = clientConn.Close()
		return
	}

	slog.Debug("CONNECT tunnel established", "target", target)

	// Bidirectional copy. Read from bufrw (which may have buffered
	// bytes the HTTP parser already pulled off the wire — typically
	// the start of the client's TLS ClientHello) and from upstream.
	// On either side closing, both directions tear down.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, bufrw)
		// Half-close upstream's write side so the target sees EOF;
		// not all conns implement CloseWrite, so fall back to full
		// close on the read side via the other goroutine's Close.
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstream)
		if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	_ = upstream.Close()
	_ = clientConn.Close()
	<-done
	slog.Debug("CONNECT tunnel closed", "target", target)
}

// normalizeConnectTarget defaults a CONNECT target without an explicit
// port to :443 (the conventional HTTPS proxy default). Returns "" for
// empty input. Handles bracketed IPv6 input ("[::1]") by stripping the
// outer brackets before joining, since net.JoinHostPort would otherwise
// double-bracket.
func normalizeConnectTarget(host string) string {
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return net.JoinHostPort(host, "443")
}

// HostOnly strips the port from a host:port string. Used by main.go.
func HostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
