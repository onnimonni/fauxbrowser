// Package solver defines the pluggable WAF challenge solver interface used
// by fauxbrowser to bypass JS-based bot gates (Cloudflare IUAM/Turnstile,
// etc.) that a pure TLS-forging proxy cannot handle on its own.
package solver

import (
	"context"
	"net/http"
	nurl "net/url"
	"time"
)

// Solver runs a real browser (in-process or out-of-process) to clear a
// JavaScript-based challenge and returns cookies + headers that fauxbrowser
// can stamp on subsequent fast-path requests.
type Solver interface {
	// Name identifies the solver in logs/metrics.
	Name() string
	// Solve navigates to target and returns the stamped cookies + User-Agent
	// after any challenge clears. The solver MUST use upstreamProxy as its
	// egress so the resulting cookies are valid for fauxbrowser's own egress
	// IP (Cloudflare binds cf_clearance to the solving IP).
	Solve(ctx context.Context, target *nurl.URL, upstreamProxy string) (*Result, error)
}

// Result is what a successful solve returns.
type Result struct {
	Cookies   []*http.Cookie
	UserAgent string
	SolvedAt  time.Time
	ExpiresAt time.Time // min(browser cookie Max-Age, conservative cap)
}
