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
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.dispatch(r)
	if err != nil {
		return nil, err
	}
	if t.opts.Rotator != nil {
		host := r.URL.Hostname()
		if fired, reason := t.opts.Rotator.RotateIfTriggered(host, resp.StatusCode, resp.Header); fired {
			slog.Info("rotation triggered by response heuristic",
				"status", resp.StatusCode, "host", host, "reason", reason)
		}
	}
	return resp, nil
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

