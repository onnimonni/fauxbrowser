package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	nurl "net/url"
)

// Options for the top-level proxy handler.
type Options struct {
	ListenAddr   string
	TargetHeader string

	// The Transport used for all upstream requests.
	Transport *Transport

	// MITM handles CONNECT tunnels. May be nil (CONNECT returns 501).
	MITM *MITM
}

// NewHandler builds the HTTP handler tree for fauxbrowser.
// It dispatches:
//   - CONNECT → MITM (in-memory TLS termination → ReverseProxy)
//   - X-Target-URL header → ReverseProxy with rewritten r.URL
//   - absolute-URI request line → ReverseProxy
//   - Host-header mode → ReverseProxy
func NewHandler(opts Options) http.Handler {
	rp := &httputil.ReverseProxy{
		// Director leaves r.URL alone — the per-mode front door has
		// already set r.URL correctly (scheme, host, path, query).
		Director: func(r *http.Request) {
			// ReverseProxy's default Director would add X-Forwarded-For
			// and strip r.RequestURI; we handle RequestURI ourselves
			// and do NOT want to leak client IP info.
		},
		Transport: opts.Transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("upstream failed", "err", err, "url", safeURL(r))
			http.Error(w, "fauxbrowser upstream: "+err.Error(), http.StatusBadGateway)
		},
		// FlushInterval -1 enables immediate flushing for streaming
		// responses (server-sent events, long polling).
		FlushInterval: -1,
	}

	listenHost := hostOnly(opts.ListenAddr)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if opts.MITM == nil {
				http.Error(w, "MITM not enabled", http.StatusNotImplemented)
				return
			}
			opts.MITM.HandleConnect(w, r)
			return
		}

		// Header mode: explicit X-Target-URL.
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

		// Classic forward-proxy: absolute-URI in the request line.
		if r.URL != nil && r.URL.IsAbs() {
			setTarget(r, r.URL)
			rp.ServeHTTP(w, r)
			return
		}

		// Host-header mode: Host names the target.
		if r.Host != "" && !IsSelfHost(r.Host, listenHost, opts.ListenAddr) {
			scheme := r.Header.Get("X-Target-Scheme")
			if scheme == "" {
				scheme = "https"
			}
			u := &nurl.URL{
				Scheme:   scheme,
				Host:     r.Host,
				Path:     r.URL.Path,
				RawQuery: r.URL.RawQuery,
			}
			setTarget(r, u)
			rp.ServeHTTP(w, r)
			return
		}

		http.Error(w, "fauxbrowser: set "+opts.TargetHeader+", send absolute-URI, or set Host header naming the target",
			http.StatusBadRequest)
	})
}

// setTarget rewrites r so ReverseProxy routes it upstream unchanged.
func setTarget(r *http.Request, u *nurl.URL) {
	r.URL = u
	r.Host = u.Host
	// RequestURI must be empty for a client (outbound) request.
	r.RequestURI = ""
}

func safeURL(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.String()
}
