package solver

import (
	"net/http"
	"strings"
)

// LooksLikeChallenge is a header-only cheap check that decides whether a
// response is worth paying the (optional) body peek + solver dispatch cost.
// It should match Cloudflare, DataDome, PerimeterX and similar.
func LooksLikeChallenge(status int, hdr http.Header) bool {
	switch status {
	case http.StatusForbidden, http.StatusServiceUnavailable, http.StatusTooManyRequests:
	default:
		return false
	}
	if strings.EqualFold(hdr.Get("Cf-Mitigated"), "challenge") {
		return true
	}
	if strings.Contains(strings.ToLower(hdr.Get("Server")), "cloudflare") &&
		hdr.Get("Cf-Ray") != "" {
		return true
	}
	// DataDome challenges set this:
	if hdr.Get("X-Dd-B") != "" || strings.Contains(hdr.Get("Set-Cookie"), "datadome") {
		return true
	}
	// PerimeterX:
	if hdr.Get("X-Px-Uuid") != "" {
		return true
	}
	return false
}

// ConfirmFromBody checks a small body buffer for challenge markers when the
// header-only signal is ambiguous.
func ConfirmFromBody(body []byte) bool {
	s := string(body)
	switch {
	case strings.Contains(s, "cdn-cgi/challenge-platform"):
		return true
	case strings.Contains(s, "__CF$cv$params"):
		return true
	case strings.Contains(s, "<title>Just a moment..."):
		return true
	case strings.Contains(s, "chk_jschl"):
		return true
	}
	return false
}
