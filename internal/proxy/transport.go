package proxy

import (
	"fmt"
	"net/http"
	nurl "net/url"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
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
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	profile := firstNonEmpty(r.Header.Get(t.opts.ProfileHeader), t.opts.DefaultProfile)
	session := r.Header.Get(t.opts.SessionHeader)

	client, err := t.clientFor(profile, session)
	if err != nil {
		return nil, err
	}

	// Build headers to forward — drop fauxbrowser control headers and
	// hop-by-hop headers per RFC 7230.
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

	// Fill in browser-plausible default headers (UA/Accept/etc.) when
	// the caller did not set them. Curl's default "User-Agent: curl/..."
	// is treated as unset since it reliably defeats the whole point of
	// TLS fingerprint forging.
	egress = applyDefaults(egress, profile)

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
	for k, vs := range egress {
		ck := fhttp.CanonicalHeaderKey(k)
		freq.Header[ck] = append(freq.Header[ck], vs...)
	}

	fresp, err := client.Do(freq)
	if err != nil {
		return nil, err
	}
	// Stream — do not read body.
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
