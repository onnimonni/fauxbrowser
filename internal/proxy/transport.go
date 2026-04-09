package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	nurl "net/url"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/onnimonni/fauxbrowser/internal/solver"
)

// TransportOptions parameterize the tls-client pool.
type TransportOptions struct {
	DefaultProfile string
	UpstreamProxy  string
	TimeoutSeconds int
	Insecure       bool

	ProfileHeader string // e.g. "X-Fauxbrowser-Profile"
	SessionHeader string // e.g. "X-Fauxbrowser-Session"
	MaxSessions   int

	// SolverCache is optional. When set, responses that look like a WAF
	// challenge trigger a solve via the wrapped Solver; resulting cookies
	// are stamped on the request and the upstream is re-fetched once.
	SolverCache  *solver.Cache
	// SolverEgress is the proxy URL the solver itself should egress via.
	// Typically differs from UpstreamProxy because the solver runs in its
	// own container and can't reach host-local addresses. Empty falls
	// back to UpstreamProxy.
	SolverEgress string
}

// Transport is an http.RoundTripper backed by a pool of tls-client clients,
// keyed by (profile, session). Empty session = cookie-neutral shared client.
type Transport struct {
	opts TransportOptions

	mu   sync.Mutex
	pool map[poolKey]tls_client.HttpClient
	lru  []poolKey
}

type poolKey struct {
	profile string
	session string
}

func NewTransport(opts TransportOptions) *Transport {
	_ = SelectProfile(opts.DefaultProfile) // validate / warn eagerly
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 256
	}
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 60
	}
	return &Transport{
		opts: opts,
		pool: make(map[poolKey]tls_client.HttpClient),
	}
}

func (t *Transport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.pool {
		c.CloseIdleConnections()
	}
	t.pool = map[poolKey]tls_client.HttpClient{}
	t.lru = nil
}

func (t *Transport) clientFor(profile, session string) (tls_client.HttpClient, error) {
	key := poolKey{profile: profile, session: session}
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.pool[key]; ok {
		if session != "" {
			t.touchLRULocked(key)
		}
		return c, nil
	}
	c, err := t.buildClient(profile, session)
	if err != nil {
		return nil, err
	}
	t.pool[key] = c
	if session != "" {
		t.lru = append(t.lru, key)
		t.evictLocked()
	}
	return c, nil
}

func (t *Transport) touchLRULocked(key poolKey) {
	for i, k := range t.lru {
		if k == key {
			t.lru = append(t.lru[:i], t.lru[i+1:]...)
			break
		}
	}
	t.lru = append(t.lru, key)
}

func (t *Transport) evictLocked() {
	for len(t.lru) > t.opts.MaxSessions {
		victim := t.lru[0]
		t.lru = t.lru[1:]
		if c, ok := t.pool[victim]; ok {
			c.CloseIdleConnections()
			delete(t.pool, victim)
		}
	}
}

func (t *Transport) buildClient(profile, session string) (tls_client.HttpClient, error) {
	p := SelectProfile(profile)
	var jar tls_client.CookieJar
	if session == "" {
		jar = noopCookieJar{}
	} else {
		jar = tls_client.NewCookieJar()
	}
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(t.opts.TimeoutSeconds),
		tls_client.WithClientProfile(p),
		tls_client.WithCookieJar(jar),
		tls_client.WithRandomTLSExtensionOrder(),
	}
	if t.opts.UpstreamProxy != "" {
		opts = append(opts, tls_client.WithProxyUrl(t.opts.UpstreamProxy))
	}
	if t.opts.Insecure {
		opts = append(opts, tls_client.WithInsecureSkipVerify())
	}
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, fmt.Errorf("tls-client new: %w", err)
	}
	return c, nil
}

// RoundTrip implements http.RoundTripper. Body is streamed; context from
// the incoming request is propagated so client disconnects cancel upstream.
// When a SolverCache is configured and the upstream response looks like a
// WAF challenge, fauxbrowser invokes the solver, stamps the resulting
// cookies + User-Agent on the request, and re-fetches once.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	profile := firstNonEmpty(r.Header.Get(t.opts.ProfileHeader), t.opts.DefaultProfile)
	session := r.Header.Get(t.opts.SessionHeader)

	// Proactively stamp cookies from a prior solve so repeat requests
	// don't re-trigger the solver on every hit.
	var primeCookies []*http.Cookie
	var primeUA string
	if t.opts.SolverCache != nil {
		if prior := t.opts.SolverCache.Peek(session, r.URL.Host); prior != nil {
			primeCookies = prior.Cookies
			primeUA = prior.UserAgent
		}
	}

	resp, err := t.dispatch(r, profile, session, primeCookies, primeUA)
	if err != nil {
		return nil, err
	}
	if t.opts.SolverCache == nil || t.opts.SolverCache.Solver() == nil {
		return resp, nil
	}
	if !solver.LooksLikeChallenge(resp.StatusCode, resp.Header) {
		return resp, nil
	}
	// If we had primed with stale cached cookies, drop them so the solver
	// gets called fresh.
	if primeCookies != nil {
		t.opts.SolverCache.Invalidate(session, r.URL.Host)
	}

	slog.Info("challenge detected, invoking solver",
		"status", resp.StatusCode, "host", r.URL.Host, "session", session)
	// Drop the challenge response body — we'll replace the whole response.
	_ = resp.Body.Close()

	solverEgress := t.opts.SolverEgress
	if solverEgress == "" {
		solverEgress = t.opts.UpstreamProxy
	}
	result, solveErr := t.opts.SolverCache.LookupOrSolve(
		r.Context(), session, r.URL, solverEgress)
	if solveErr != nil || result == nil {
		slog.Warn("solver failed; returning original challenge response",
			"err", solveErr)
		// Re-issue the fetch so the caller at least sees a body.
		return t.dispatch(r, profile, session, nil, "")
	}

	retryResp, err := t.dispatch(r, profile, session, result.Cookies, result.UserAgent)
	if err != nil {
		return nil, err
	}
	// If the retry STILL looks like a challenge, invalidate and bail —
	// the cached cookies are stale or the solver's IP no longer matches.
	if solver.LooksLikeChallenge(retryResp.StatusCode, retryResp.Header) {
		slog.Warn("re-fetch after solve still challenged; invalidating",
			"host", r.URL.Host)
		t.opts.SolverCache.Invalidate(session, r.URL.Host)
	}
	return retryResp, nil
}

// dispatch performs one upstream fetch via the (profile, session) client.
// Optional stampCookies/stampUA override the request cookies/UA — used by
// the solver retry path.
func (t *Transport) dispatch(r *http.Request, profile, session string, stampCookies []*http.Cookie, stampUA string) (*http.Response, error) {
	client, err := t.clientFor(profile, session)
	if err != nil {
		return nil, err
	}

	egress := cloneHeader(r.Header)
	for _, h := range []string{
		t.opts.ProfileHeader,
		t.opts.SessionHeader,
		"X-Target-URL",
		"X-Target-Scheme",
		"Proxy-Authorization",
		"Proxy-Connection",
	} {
		egress.Del(h)
	}
	for _, h := range hopByHopFromConnection(r.Header) {
		egress.Del(h)
	}
	for _, h := range staticHopByHop {
		egress.Del(h)
	}
	egress = applyDefaults(egress, profile)

	if stampUA != "" {
		egress.Set("User-Agent", stampUA)
	}
	if len(stampCookies) > 0 {
		// Merge into any existing Cookie header.
		existing := egress.Get("Cookie")
		var parts []string
		if existing != "" {
			parts = append(parts, existing)
		}
		for _, c := range stampCookies {
			parts = append(parts, c.Name+"="+c.Value)
		}
		egress.Set("Cookie", strings.Join(parts, "; "))
	}

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
	// Replace tls-client's per-profile default headers with ours. tls-client
	// pre-populates freq.Header (including an older User-Agent) from the
	// selected ClientProfile; using Set + Del guarantees our values win.
	for k, vs := range egress {
		ck := fhttp.CanonicalHeaderKey(k)
		freq.Header.Del(ck)
		for _, v := range vs {
			freq.Header.Add(ck, v)
		}
	}

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
	return out, nil
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

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// --- cookie-neutral jar ---

type noopCookieJar struct{}

func (noopCookieJar) SetCookies(_ *nurl.URL, _ []*fhttp.Cookie)    {}
func (noopCookieJar) Cookies(_ *nurl.URL) []*fhttp.Cookie          { return nil }
func (noopCookieJar) GetAllCookies() map[string][]*fhttp.Cookie    { return nil }
