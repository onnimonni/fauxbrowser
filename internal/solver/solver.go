// Package solver provides on-demand WAF challenge solving for
// fauxbrowser. When the rotator's heuristic detects an upstream
// response that looks like a Cloudflare IUAM / Turnstile / Akamai
// Bot Manager / DataDome / PerimeterX / Imperva challenge, the
// transport invokes a Solver implementation that fetches the target
// URL through a real browser, captures the WAF clearance cookies,
// and returns them. The transport then stamps those cookies on a
// one-shot retry of the original request.
//
// Implementations:
//
//   - solver/chromedp: launches a fresh headless Chromium per solve
//     (no warm pool), routes Chromium's traffic back through
//     fauxbrowser's CONNECT mode so the solve happens via the same
//     WireGuard exit IP as the rest of the proxy. This is the
//     elegant property: cookies bound to (host, exit_ip) are valid
//     for subsequent fauxbrowser fast-path requests because the
//     exit IP is the same.
//
// The Solver interface is intentionally narrow so additional
// backends (FlareSolverr sidecar, custom HTTP solver service) can
// be plugged in later without touching the transport.
package solver

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Solver fetches a target URL through a real browser and returns
// the cookies + headers that constitute a "solved" session. Each
// invocation is a fresh solve — implementations should NOT cache
// internally; the Cache wrapper above the Solver does that.
type Solver interface {
	// Solve drives a real browser at target and returns the
	// resulting Solution. The context's deadline bounds the entire
	// browser session.
	Solve(ctx context.Context, target *url.URL) (*Solution, error)

	// Name returns a stable identifier for logging.
	Name() string

	// Close releases any persistent resources held by the solver
	// (e.g. shared chromedp allocator). Most on-demand
	// implementations have nothing to close.
	Close() error
}

// Solution is what a Solver returns after a successful solve.
type Solution struct {
	// Cookies is the WAF clearance cookies extracted from the
	// browser session (cf_clearance, _abck, datadome, _px3, etc.)
	// plus any other cookies the target set during the solve.
	Cookies []*http.Cookie

	// UserAgent is the User-Agent the solver used. Stamping the
	// returned cookies on a subsequent fauxbrowser request only
	// works if that request uses the same UA — most WAFs bind
	// clearance cookies to the (UA, IP) tuple. fauxbrowser sets
	// this to the chrome146 profile UA so the cookies stay valid
	// on the fast path.
	UserAgent string

	// SolvedAt is the wall-clock time of the successful solve.
	SolvedAt time.Time
}

// Cookie returns the value of a named cookie from the solution, or
// "" if not present.
func (s *Solution) Cookie(name string) string {
	for _, c := range s.Cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}
