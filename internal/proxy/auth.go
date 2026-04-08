// Bearer-token auth middleware.
//
// fauxbrowser defaults to binding on 127.0.0.1 with no auth, because
// the expected deployment is a sidecar next to a single Elixir worker.
// If the operator binds either the proxy or admin listener to a non-
// loopback interface, main.go's safetyCheck REFUSES to start without
// a token set.
//
// Token comparison uses subtle.ConstantTimeCompare so failed attempts
// don't leak timing information. An empty token means "auth disabled"
// and the middleware is a no-op pass-through — this is the loopback
// default.
package proxy

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// BearerAuth wraps h with a bearer-token check. If token is empty, the
// returned handler is h unchanged (auth disabled). Non-empty tokens
// require every request to present a bearer credential in either
// `Authorization: Bearer <token>` (the API mode) OR
// `Proxy-Authorization: Bearer <token>` (the HTTP_PROXY/CONNECT mode).
//
// On failure, CONNECT requests get 407 Proxy Authentication Required
// (with Proxy-Authenticate); everything else gets 401 Unauthorized
// (with WWW-Authenticate).
func BearerAuth(h http.Handler, token string) http.Handler {
	if token == "" {
		return h
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := extractBearer(r.Header.Get("Authorization"))
		if got == "" {
			got = extractBearer(r.Header.Get("Proxy-Authorization"))
		}
		if got == "" || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			if r.Method == http.MethodConnect {
				w.Header().Set("Proxy-Authenticate", `Bearer realm="fauxbrowser"`)
				http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="fauxbrowser"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// extractBearer returns the token portion of an "Authorization: Bearer <tok>"
// header value. Case-insensitive on the scheme. Returns "" if the header
// isn't a bearer grant.
func extractBearer(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}
