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
// require every request to present
// "Authorization: Bearer <token>" — any other value (missing, wrong
// scheme, wrong value) returns 401.
func BearerAuth(h http.Handler, token string) http.Handler {
	if token == "" {
		return h
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := extractBearer(r.Header.Get("Authorization"))
		if got == "" || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
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
