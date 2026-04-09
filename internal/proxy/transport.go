// Package proxy holds the forwarder transport and the plaintext h2c
// listener handler.
//
// The transport wraps a single tls-client (profile selected via
// SelectProfile, see profiles.go) dispatched via a custom ContextDialer
// provided by the rotator, which routes through the current WireGuard
// tunnel. It:
//
//  1. Forges the selected browser's TLS fingerprint + header bundle on
//     every outbound request.
//  2. Honors caller-set Cookie headers as-is (those are "the client's
//     cookies" — not ours) and never clears them from the incoming
//     request.
//  3. Maintains an internal cookie jar per tls-client so upstream
//     Set-Cookie headers persist across requests from the same worker.
//     The jar is cleared on rotation.
//  4. After receiving a response, runs the rotator's 429/403 heuristic
//     and asynchronously triggers a rotation if matched. The caller
//     still gets the current response; the rotation affects subsequent
//     requests.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"golang.org/x/net/proxy"

	"github.com/onnimonni/fauxbrowser/internal/solver"
)

// RotationHook is called with every upstream response so the rotator
// can decide whether to rotate. The host parameter drives the
// rotator's per-host quarantine and debounce logic.
type RotationHook interface {
	RotateIfTriggered(host string, status int, h http.Header) (bool, string)
}

// TransportOptions parameterize the tls-client transport.
type TransportOptions struct {
	// Dialer routes outbound TCP through the WireGuard tunnel. Must be
	// non-nil — fauxbrowser has no bare-metal fallback.
	Dialer proxy.ContextDialer

	// TimeoutSeconds is the per-request upstream timeout.
	TimeoutSeconds int

	// Profile selects the (TLS fingerprint, UA, Client-Hints) bundle.
	// Empty = DefaultProfile (chrome146). Unknown values fall back to
	// DefaultProfile with a slog.Warn.
	Profile string

	// Rotator is notified of every upstream response. May be nil in
	// tests.
	Rotator RotationHook

	// SolverCache is an optional WAF-challenge solver cache. When
	// set, dispatch() will:
	//   1. Proactively stamp cached cookies on outbound requests
	//      whose (host, exit_ip) is in the cache.
	//   2. After receiving a response, if it matches a known
	//      challenge fingerprint AND the cache had no fresh entry,
	//      invoke the solver, cache the result, and one-shot retry
	//      with the new cookies stamped on.
	//
	// Nil = solver disabled. The fast path stays unchanged in that
	// case.
	SolverCache *solver.Cache

	// ExitIPProvider returns the current exit IP for solver cache
	// keying. Called on every request, so it must be cheap. Nil =
	// solver disabled (the cache key needs the exit IP to be
	// meaningful — without it, cookies from different exits would
	// pollute each other).
	ExitIPProvider func() string
}

// Transport is an http.RoundTripper backed by a single tls-client with
// a pinned browser profile. The client is rebuilt on RotateJar() which
// is how the rotator clears cookie state after an IP swap.
type Transport struct {
	opts    TransportOptions
	profile BrowserProfile

	mu     sync.RWMutex
	client tls_client.HttpClient
}

// NewTransport constructs a Transport and builds its initial client.
func NewTransport(opts TransportOptions) (*Transport, error) {
	if opts.Dialer == nil {
		return nil, fmt.Errorf("transport: Dialer is required")
	}
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 60
	}
	t := &Transport{
		opts:    opts,
		profile: SelectProfile(opts.Profile),
	}
	if err := t.rebuildClient(); err != nil {
		return nil, err
	}
	return t, nil
}

// Profile returns the resolved browser profile this transport is using.
func (t *Transport) Profile() BrowserProfile { return t.profile }

func (t *Transport) rebuildClient() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		t.client.CloseIdleConnections()
	}
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(t.opts.TimeoutSeconds),
		tls_client.WithClientProfile(t.profile.TLSProfile),
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithProxyDialerFactory(func(
			_ string,
			_ time.Duration,
			_ *net.TCPAddr,
			_ fhttp.Header,
			_ tls_client.Logger,
		) (proxy.ContextDialer, error) {
			return t.opts.Dialer, nil
		}),
	}
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return fmt.Errorf("tls-client new: %w", err)
	}
	t.client = c
	return nil
}

// RotateJar clears all cookies held by the tls-client jar and rebuilds
// the client. Called by the rotator after an IP swap so we never leak
// cookies bound to the old exit IP.
//
// Caller-supplied Cookie request headers are untouched — they live on
// the inbound *http.Request and are re-sent verbatim by dispatch().
func (t *Transport) RotateJar() error {
	return t.rebuildClient()
}

func (t *Transport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		t.client.CloseIdleConnections()
		t.client = nil
	}
}

// RoundTrip implements http.RoundTripper.
//
// Flow:
//
//  1. If a SolverCache is configured AND the (host, exit_ip) has a
//     fresh cached solution, stamp those cookies on the outbound
//     request before dispatch. This is the proactive path: known
//     challenged hosts skip the solver entirely on every repeat
//     visit.
//  2. Dispatch the request via tls-client.
//  3. If the response is a known WAF challenge AND we have a
//     solver, drain the response body, invoke the solver via the
//     cache (singleflight-deduped), then re-dispatch the original
//     request with the new cookies stamped on. Return the retry
//     response.
//  4. Notify the rotator of the (final) response so its 429/403
//     heuristic can fire if applicable.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	host := r.URL.Hostname()
	exitIP := ""
	if t.opts.ExitIPProvider != nil {
		exitIP = t.opts.ExitIPProvider()
	}

	// Step 1: proactive cookie stamping.
	var cachedSol *solver.Solution
	if t.opts.SolverCache != nil && exitIP != "" {
		cachedSol = t.opts.SolverCache.Lookup(host, exitIP)
		if cachedSol != nil {
			stampSolutionCookies(r, cachedSol)
		}
	}

	resp, err := t.dispatch(r)
	if err != nil {
		return nil, err
	}

	// Step 2: solver path. Only if a solver is configured AND the
	// response looks like a known challenge AND we haven't already
	// proactively stamped cached cookies (if we did and it STILL
	// failed, that's a circuit-breaker case — running the solver
	// again would just produce the same cookies and loop).
	if t.opts.SolverCache != nil && exitIP != "" && cachedSol == nil {
		kind := solver.DetectChallenge(resp.StatusCode, resp.Header)
		if kind.Solvable() {
			// Circuit breaker short-circuit: if previous attempts
			// on this host have repeatedly failed to satisfy the
			// WAF after cookie stamping, the circuit is open and
			// we skip the (expensive) solver entirely. Pass the
			// challenge response through to the caller as-is.
			// The circuit auto-closes after the configured
			// open-for duration.
			if t.opts.SolverCache.CircuitOpen(host) {
				slog.Warn("solver path: circuit open for host, skipping solver",
					"host", host, "exit_ip", exitIP, "kind", kind.String(),
					"status", resp.StatusCode)
			} else {
				slog.Info("solver path: challenge detected, invoking solver",
					"host", host, "exit_ip", exitIP, "kind", kind.String(),
					"status", resp.StatusCode)
				// Drop the challenge response body, we'll replace it.
				_ = resp.Body.Close()
				retryResp, solveErr := t.solveAndRetry(r, host, exitIP)
				if solveErr != nil {
					slog.Warn("solver path: solve failed, returning last response",
						"host", host, "err", solveErr)
					resp, err = t.dispatch(r)
					if err != nil {
						return nil, err
					}
				} else {
					resp = retryResp
					// If the retry STILL looks challenged, the
					// cookies didn't satisfy the WAF (most likely
					// the WAF pins cf_clearance to the solver
					// browser's TLS fingerprint / socket, not just
					// the JA4 we match on the fast path). Mark the
					// failure, invalidate the cache entry, and
					// pass the 4xx through. After cbThreshold
					// consecutive failures the circuit opens and
					// the next request skips the solver entirely.
					if solver.DetectChallenge(retryResp.StatusCode, retryResp.Header).Solvable() {
						t.opts.SolverCache.Invalidate(host, exitIP)
						opened := t.opts.SolverCache.MarkRetryFailed(host)
						if opened {
							slog.Warn("solver path: circuit breaker OPENED for host — skipping solver for this host until cool-down",
								"host", host, "exit_ip", exitIP, "status", retryResp.StatusCode)
						} else {
							slog.Warn("solver path: retry STILL challenged — invalidating cache, propagating 4xx to caller",
								"host", host, "exit_ip", exitIP, "status", retryResp.StatusCode)
						}
					} else {
						// Retry cleared the challenge — reset the
						// host's failure counter so a transient
						// glitch doesn't count against a healthy
						// host.
						t.opts.SolverCache.MarkRetrySucceeded(host)
					}
				}
			}
		}
	}

	// Step 3: rotator notification.
	if t.opts.Rotator != nil {
		if fired, reason := t.opts.Rotator.RotateIfTriggered(host, resp.StatusCode, resp.Header); fired {
			slog.Info("rotation triggered by response heuristic",
				"status", resp.StatusCode, "host", host, "reason", reason)
		}
	}
	return resp, nil
}

// solveAndRetry runs the solver via the cache and re-dispatches
// the original request with the new cookies stamped on.
func (t *Transport) solveAndRetry(orig *http.Request, host, exitIP string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(orig.Context(), 60*time.Second)
	defer cancel()
	sol, err := t.opts.SolverCache.LookupOrSolve(ctx, orig.URL, exitIP)
	if err != nil {
		return nil, err
	}
	stampSolutionCookies(orig, sol)
	return t.dispatch(orig)
}

// stampSolutionCookies merges the solver's cookies into the
// request's existing Cookie header. If the caller already provided
// a Cookie header it's preserved verbatim and the solver cookies
// are appended.
func stampSolutionCookies(r *http.Request, sol *solver.Solution) {
	if sol == nil || len(sol.Cookies) == 0 {
		return
	}
	parts := make([]string, 0, len(sol.Cookies)+1)
	if existing := r.Header.Get("Cookie"); existing != "" {
		parts = append(parts, existing)
	}
	for _, c := range sol.Cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	r.Header.Set("Cookie", strings.Join(parts, "; "))
}

func (t *Transport) dispatch(r *http.Request) (*http.Response, error) {
	t.mu.RLock()
	client := t.client
	t.mu.RUnlock()
	if client == nil {
		return nil, fmt.Errorf("transport closed")
	}

	egress := scrubOutboundHeaders(r.Header)
	egress = applyProfileDefaults(egress, t.profile)

	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	freq, err := fhttp.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), body)
	if err != nil {
		return nil, err
	}
	freq.ContentLength = r.ContentLength
	freq.Host = r.Host
	// Replace tls-client's per-profile default headers with ours.
	for k, vs := range egress {
		ck := fhttp.CanonicalHeaderKey(k)
		freq.Header.Del(ck)
		for _, v := range vs {
			freq.Header.Add(ck, v)
		}
	}
	// Pin regular header order to match Chrome 146's exact order.
	// fhttp uses HeaderOrderKey to control the h2 HEADERS frame
	// serialization; without it, Go's map iteration order produces
	// a random/inconsistent order that some WAFs fingerprint.
	freq.Header[fhttp.HeaderOrderKey] = chromeHeaderOrder

	fresp, err := client.Do(freq)
	if err != nil {
		return nil, err
	}
	out := &http.Response{
		Status:        fresp.Status,
		StatusCode:    fresp.StatusCode,
		Proto:         fresp.Proto,
		ProtoMajor:    fresp.ProtoMajor,
		ProtoMinor:    fresp.ProtoMinor,
		Header:        http.Header{},
		Body:          fresp.Body,
		ContentLength: fresp.ContentLength,
		Request:       r,
	}
	for k, vs := range fresp.Header {
		ck := http.CanonicalHeaderKey(k)
		out.Header[ck] = append(out.Header[ck], vs...)
	}
	// Issue #1: tls-client auto-decompresses gzip/br/zstd response
	// bodies but the upstream Content-Encoding + Content-Length
	// headers still describe the COMPRESSED bytes. Forwarding both
	// unchanged makes downstream HTTP parsers (Mint, Finch, Hyper,
	// curl) see a body shorter than the advertised Content-Length
	// and report the response as truncated.
	//
	// Fix: when the upstream said the body was compressed, drop
	// Content-Encoding and Content-Length, set out.ContentLength
	// to -1 so net/http forces chunked transfer-encoding on the
	// wire to the downstream client. The body bytes we serve are
	// already plain-text (tls-client decompressed them) so this
	// is consistent end-to-end.
	if ce := strings.ToLower(out.Header.Get("Content-Encoding")); ce != "" && ce != "identity" {
		out.Header.Del("Content-Encoding")
		out.Header.Del("Content-Length")
		out.ContentLength = -1
	}
	return out, nil
}

// scrubOutboundHeaders clones the incoming request headers and removes
// everything that must not reach the upstream target: fauxbrowser
// control headers, hop-by-hop headers (RFC 7230 §6.1), and anonymity-
// breaking forwarding headers. Pure function — called from dispatch()
// and tested directly.
func scrubOutboundHeaders(in http.Header) http.Header {
	out := cloneHeader(in)
	for _, h := range fauxbrowserControlHeaders {
		out.Del(h)
	}
	for _, h := range hopByHopFromConnection(in) {
		out.Del(h)
	}
	for _, h := range staticHopByHop {
		out.Del(h)
	}
	for _, h := range anonymityScrub {
		out.Del(h)
	}
	return out
}

// fauxbrowserControlHeaders are meta-headers the proxy uses to route
// requests; they must never leak to the target.
var fauxbrowserControlHeaders = []string{
	"X-Target-URL",
	"X-Target-Scheme",
	"Proxy-Authorization",
	"Proxy-Connection",
}

var staticHopByHop = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// anonymityScrub is the set of headers that would leak origin IPs,
// proxy topology, or internal infrastructure details if forwarded to
// the target. Stripped unconditionally in dispatch().
var anonymityScrub = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Real-Ip",
	"X-Client-Ip",
	"X-Originating-Ip",
	"X-Remote-Ip",
	"X-Remote-Addr",
	"Cf-Connecting-Ip",
	"True-Client-Ip",
	"Fastly-Client-Ip",
	"X-Cluster-Client-Ip",
	"Via",
	"Forwarded", // RFC 7239
	"X-Proxy-User",
	"X-Proxyuser-Ip",
}

func hopByHopFromConnection(h http.Header) []string {
	var names []string
	for _, v := range h.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				names = append(names, t)
			}
		}
	}
	return names
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

