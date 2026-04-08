package proxy

import (
	"encoding/base64"
	"net/http"
	nurl "net/url"
	"path"
	"strings"
)

// BasicAuth wraps h with a Proxy-Authorization: Basic gate.
// Empty expected value disables the gate.
func BasicAuth(h http.Handler, expected string) http.Handler {
	if expected == "" {
		return h
	}
	token := "Basic " + base64.StdEncoding.EncodeToString([]byte(expected))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != token {
			w.Header().Set("Proxy-Authenticate", `Basic realm="fauxbrowser"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
		r.Header.Del("Proxy-Authorization")
		h.ServeHTTP(w, r)
	})
}

// HostAllowList wraps h and 403s requests whose effective target host does
// not match any glob pattern. Globs use filepath-style `*` matching against
// the host portion only. Empty list = allow any.
func HostAllowList(h http.Handler, globs []string, targetHeader string) http.Handler {
	if len(globs) == 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := extractTargetHost(r, targetHeader)
		if target == "" || !matchAny(target, globs) {
			http.Error(w, "fauxbrowser: host not in allow-list", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func extractTargetHost(r *http.Request, targetHeader string) string {
	if r.Method == http.MethodConnect {
		return hostOnly(r.Host)
	}
	if v := r.Header.Get(targetHeader); v != "" {
		if u, err := nurl.Parse(v); err == nil {
			return hostOnly(u.Host)
		}
	}
	if r.URL != nil && r.URL.IsAbs() {
		return hostOnly(r.URL.Host)
	}
	return hostOnly(r.Host)
}

func hostOnly(hostport string) string {
	if i := strings.IndexByte(hostport, ':'); i >= 0 {
		return hostport[:i]
	}
	return hostport
}

func matchAny(host string, globs []string) bool {
	for _, g := range globs {
		if ok, err := path.Match(g, host); err == nil && ok {
			return true
		}
	}
	return false
}
