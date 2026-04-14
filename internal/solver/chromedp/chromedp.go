// Package chromedp implements solver.Solver via a real headless
// Chromium process driven by github.com/chromedp/chromedp.
//
// Design choices:
//
//   - **No warm pool.** Each solve cold-starts a fresh Chromium
//     process. The user-supplied requirement: pay the ~500ms-2s
//     startup cost to keep memory pressure to zero between solves.
//     The cookie cache (solver.Cache) ensures most requests skip
//     the solver entirely after the first solve per (host, exit_ip).
//
//   - **Routes through fauxbrowser CONNECT.** Chromium's
//     `--proxy-server` flag is set to fauxbrowser's own listen
//     address. The CONNECT path tunnels Chromium's encrypted
//     traffic through the same WireGuard exit IP that the
//     X-Target-URL fast path uses, so the cookies Chromium gets
//     back are valid for that exit IP. This is the elegant
//     composition that makes the solver actually useful — without
//     it, Chromium would dial directly from the host and the
//     cookies would be tied to a different IP.
//
//   - **Forces the chrome146 User-Agent.** Most WAFs bind clearance
//     cookies to the (UA, IP) tuple. By making Chromium use the
//     same UA fauxbrowser will send on subsequent fast-path
//     requests, the cookies stay valid. (Chromium's "real" UA would
//     be ignored — Cloudflare, Akamai, etc. care about the string,
//     not whether it came from a real browser.)
//
//   - **Sandbox handling.** Chromium needs `--no-sandbox` when
//     running as root or inside an unprivileged systemd unit
//     without user namespaces. We enable it unconditionally because
//     we're solving WAF challenges, not loading hostile content.
//
//   - **No persistent profile.** Each solve runs in a fresh
//     `--user-data-dir` (Chromium picks a temp dir per launch).
//     This guarantees no cookies leak between solves and that the
//     fingerprint surface stays consistent.
package chromedp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/onnimonni/fauxbrowser/internal/solver"
)

// Options configures the chromedp solver.
type Options struct {
	// UpstreamProxy is the URL Chromium dials all its HTTP/HTTPS
	// traffic through. Typically the fauxbrowser listen address
	// (e.g. http://127.0.0.1:18443). REQUIRED — without this the
	// solver dials directly from the host and the cookies are tied
	// to the wrong exit IP.
	UpstreamProxy string

	// UserAgent is forced on Chromium via --user-agent. Should
	// match the chrome146 profile UA fauxbrowser uses on the fast
	// path so cookies remain valid for subsequent fauxbrowser
	// requests.
	UserAgent string

	// SolveTimeout is the max time the entire browser session can
	// take. Includes startup, navigation, challenge solve, and
	// cookie extraction. Default 30s.
	SolveTimeout time.Duration

	// ExtraFlags are appended to the chromedp ExecAllocator flags.
	// Useful for --disable-features or other custom tweaks.
	ExtraFlags map[string]any

	// ChromiumPath is the absolute path to the Chromium binary.
	// If empty, chromedp's default binary lookup is used (PATH).
	ChromiumPath string

	// Logf is an optional structured log target.
	Logf func(msg string, args ...any)
}

// Solver is the chromedp implementation of solver.Solver.
type Solver struct {
	opts Options
}

// New constructs a Solver. ChromiumAvailable() should be called
// first to verify Chromium is on PATH (or at ChromiumPath); New
// itself does not validate the binary.
func New(opts Options) *Solver {
	if opts.SolveTimeout <= 0 {
		opts.SolveTimeout = 30 * time.Second
	}
	if opts.Logf == nil {
		opts.Logf = func(msg string, args ...any) {}
	}
	return &Solver{opts: opts}
}

// Name returns "chromedp".
func (s *Solver) Name() string { return "chromedp" }

// Close is a no-op — this implementation has no persistent state.
func (s *Solver) Close() error { return nil }

// Solve launches a fresh Chromium, navigates to target, waits for
// the WAF clearance cookies to appear, extracts them, and returns
// a Solution.
func (s *Solver) Solve(ctx context.Context, target *url.URL) (*solver.Solution, error) {
	if s.opts.UpstreamProxy == "" {
		return nil, errors.New("chromedp solver: UpstreamProxy is required")
	}

	// Wrap the parent context with the solve deadline.
	ctx, cancelDeadline := context.WithTimeout(ctx, s.opts.SolveTimeout)
	defer cancelDeadline()

	// Build the chromedp ExecAllocator with all the flags we need.
	flags := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-gpu", true),
		chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.ProxyServer(s.opts.UpstreamProxy),
		chromedp.Flag("ignore-certificate-errors", true),
	)
	if s.opts.UserAgent != "" {
		flags = append(flags, chromedp.UserAgent(s.opts.UserAgent))
	}
	if s.opts.ChromiumPath != "" {
		flags = append(flags, chromedp.ExecPath(s.opts.ChromiumPath))
	}
	for k, v := range s.opts.ExtraFlags {
		flags = append(flags, chromedp.Flag(k, v))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, flags...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	s.opts.Logf("solver: launching chromedp",
		"target", target.String(),
		"proxy", s.opts.UpstreamProxy,
		"timeout", s.opts.SolveTimeout.String())

	// Navigate, give the page enough time to solve any JS
	// challenge it serves, then extract cookies.
	//
	// Strategy: navigate, then poll for either (a) the cf_clearance
	// / _abck / datadome cookie to appear, or (b) the document
	// title to stop being a known challenge title. Bail at the
	// solve timeout.
	var cookies []*network.Cookie
	err := chromedp.Run(browserCtx,
		network.Enable(),
		chromedp.Navigate(target.String()),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return s.waitForSolve(ctx, target.Host)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			cookies, err = network.GetCookies().Do(ctx)
			return err
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("chromedp solve: %w", err)
	}

	httpCookies := convertCookies(cookies, target.Host)
	// Some WAFs (e.g. Vercel) set session cookies that are domain-scoped
	// broadly; if domain filtering eliminated all cookies, fall back to
	// returning ALL cookies so the retry path has something to stamp.
	if len(httpCookies) == 0 {
		httpCookies = convertAllCookies(cookies)
		if len(httpCookies) == 0 {
			return nil, errors.New("chromedp solve: no cookies returned (challenge may not have completed)")
		}
	}

	cookieNames := make([]string, 0, len(httpCookies))
	for _, c := range httpCookies {
		cookieNames = append(cookieNames, c.Name)
	}
	s.opts.Logf("solver: chromedp solved",
		"target", target.String(),
		"cookies", len(httpCookies),
		"cookie_names", strings.Join(cookieNames, ","))

	return &solver.Solution{
		Cookies:   httpCookies,
		UserAgent: s.opts.UserAgent,
		SolvedAt:  time.Now(),
	}, nil
}

// waitForSolve polls the browser session every 250ms until a
// recognizable WAF clearance cookie appears, or the context expires.
//
// Why we DON'T return early on "title is not a challenge title":
// Cloudflare Turnstile and managed-challenge pages often have a
// title that matches the target site (not "Just a moment...") even
// while the Turnstile widget is still grinding in the background.
// Returning early gives us a Chromium session that holds session
// cookies but NOT the cf_clearance cookie that actually grants
// access. The fauxbrowser retry then stamps useless cookies and
// gets a fresh 403.
//
// Instead we wait until a known clearance cookie name actually
// appears in the browser's cookie store. The deadline is the
// solve timeout minus 1 second.
// knownChallengeTitles is a set of page titles that indicate a WAF
// challenge is still in progress. When a Chromium session's title
// leaves this set (and a settle delay passes), the challenge is
// considered solved even if no known clearance cookie is present.
// This is necessary for WAFs (like Vercel) that use cookie names
// we can't enumerate in advance.
var knownChallengeTitles = []string{
	"just a moment",           // Cloudflare IUAM / Turnstile
	"vercel security checkpoint", // Vercel bot protection
	"security check",          // generic checkpoint pages
	"access denied",           // pre-challenge denial page
	"please wait",             // generic wait pages
	"ddos-guard",              // DDoS-Guard
	"checking your browser",   // generic checks
}

func (s *Solver) waitForSolve(ctx context.Context, host string) error {
	// Cookie names that signal a solve is complete for specific WAFs.
	clearanceCookieNames := []string{
		"cf_clearance", "_abck", "datadome", "_px3", "incap_ses_",
		// Vercel bot protection cookies
		"_vcrocs", "__vcz_challenge", "_vercel_jwt",
	}

	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(s.opts.SolveTimeout - time.Second)
	defer deadline.Stop()

	// Initial render delay so the challenge JS has time to start.
	select {
	case <-time.After(1 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}

	for {
		// Check cookies first — definitive signal for known WAFs.
		cookies, err := network.GetCookies().Do(ctx)
		if err == nil {
			for _, c := range cookies {
				for _, want := range clearanceCookieNames {
					if strings.HasPrefix(c.Name, want) {
						select {
						case <-time.After(500 * time.Millisecond):
						case <-ctx.Done():
							return ctx.Err()
						}
						return nil
					}
				}
			}
		}

		// Fallback: check if the page title has left the challenge
		// set. Vercel's checkpoint and similar JS-challenge pages
		// redirect/rewrite the title once the PoW passes; if the
		// title is no longer a known challenge title the cookies
		// should be stable.
		var title string
		if titleErr := chromedp.Title(&title).Do(ctx); titleErr == nil {
			titleLower := strings.ToLower(strings.TrimSpace(title))
			isChallenge := false
			for _, ct := range knownChallengeTitles {
				if strings.Contains(titleLower, ct) {
					isChallenge = true
					break
				}
			}
			if !isChallenge && title != "" {
				// Title is no longer a challenge page. Wait a bit
				// for cookies to settle, then return.
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
					return ctx.Err()
				}
				return nil
			}
		}

		select {
		case <-tick.C:
		case <-deadline.C:
			return errors.New("waitForSolve: deadline exceeded — no clearance cookie or title change observed")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// convertCookies translates chromedp's network.Cookie into
// http.Cookie, keeping only cookies that apply to the target host.
func convertCookies(cookies []*network.Cookie, targetHost string) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		domain := strings.TrimPrefix(c.Domain, ".")
		if domain != targetHost && !strings.HasSuffix(targetHost, "."+domain) {
			continue
		}
		out = append(out, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		})
	}
	return out
}

// convertAllCookies is a fallback that converts all cookies without
// host-based filtering. Used when convertCookies returns empty (e.g.
// Vercel sets cookies on broad domains that don't match targetHost).
func convertAllCookies(cookies []*network.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		})
	}
	return out
}

// ChromiumAvailable returns true if a Chromium binary is callable
// at path (or, if path is empty, on PATH). Used by main.go's
// safetyCheck to refuse to start with -solver chromedp when
// Chromium is missing.
func ChromiumAvailable(path string) bool {
	if path != "" {
		_, err := exec.LookPath(path)
		return err == nil
	}
	for _, name := range []string{"chromium", "chrome", "google-chrome", "google-chrome-stable", "chromium-browser"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}
