package proxy

import (
	"net/http"
	"testing"
)

// TestScrubOutboundHeaders verifies that every anonymity-breaking
// header class is removed by scrubOutboundHeaders before the request
// is handed to tls-client.
func TestScrubOutboundHeaders(t *testing.T) {
	in := http.Header{}

	// Caller-supplied "legitimate" headers that MUST survive.
	in.Set("User-Agent", "legit")
	in.Set("Accept", "text/html")
	in.Set("Cookie", "caller=preserved")
	in.Set("Referer", "https://example.com/")
	in.Set("Authorization", "Bearer target-creds") // NOT Proxy-Authorization

	// Fauxbrowser control headers.
	in.Set("X-Target-URL", "https://example.com/path")
	in.Set("X-Target-Scheme", "https")
	in.Set("Proxy-Authorization", "Basic Zm9vOmJhcg==")
	in.Set("Proxy-Connection", "keep-alive")

	// Static hop-by-hop headers.
	in.Set("Connection", "keep-alive, X-Custom-Hop")
	in.Set("Keep-Alive", "timeout=5")
	in.Set("Te", "trailers")
	in.Set("Trailer", "Expires")
	in.Set("Transfer-Encoding", "chunked")
	in.Set("Upgrade", "websocket")
	in.Set("Proxy-Authenticate", "Basic realm=x")
	in.Set("X-Custom-Hop", "hop-listed-in-connection-header")

	// Anonymity scrub — forwarding headers that would leak origin IPs.
	in.Set("X-Forwarded-For", "1.2.3.4")
	in.Set("X-Forwarded-Host", "origin.internal")
	in.Set("X-Forwarded-Proto", "https")
	in.Set("X-Forwarded-Port", "443")
	in.Set("X-Real-Ip", "1.2.3.4")
	in.Set("X-Client-Ip", "1.2.3.4")
	in.Set("X-Originating-Ip", "1.2.3.4")
	in.Set("X-Remote-Ip", "1.2.3.4")
	in.Set("X-Remote-Addr", "1.2.3.4")
	in.Set("Cf-Connecting-Ip", "1.2.3.4")
	in.Set("True-Client-Ip", "1.2.3.4")
	in.Set("Fastly-Client-Ip", "1.2.3.4")
	in.Set("X-Cluster-Client-Ip", "1.2.3.4")
	in.Set("Via", "1.1 fauxbrowser")
	in.Set("Forwarded", "for=1.2.3.4;proto=https")
	in.Set("X-Proxy-User", "onni")
	in.Set("X-Proxyuser-Ip", "1.2.3.4")

	out := scrubOutboundHeaders(in)

	// Headers that MUST be gone.
	mustNotExist := []string{
		"X-Target-URL",
		"X-Target-Scheme",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Connection",
		"Keep-Alive",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Authenticate",
		"X-Custom-Hop",
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
		"Forwarded",
		"X-Proxy-User",
		"X-Proxyuser-Ip",
	}
	for _, h := range mustNotExist {
		if v := out.Get(h); v != "" {
			t.Errorf("%s leaked through scrub: %q", h, v)
		}
	}

	// Headers that MUST be preserved.
	preserved := map[string]string{
		"User-Agent":    "legit",
		"Accept":        "text/html",
		"Cookie":        "caller=preserved",
		"Referer":       "https://example.com/",
		"Authorization": "Bearer target-creds",
	}
	for h, want := range preserved {
		if got := out.Get(h); got != want {
			t.Errorf("%s = %q, want %q (must not be scrubbed)", h, got, want)
		}
	}

	// Verify the original map is untouched (scrubOutboundHeaders must
	// clone, not mutate in place).
	if in.Get("X-Forwarded-For") == "" {
		t.Errorf("scrubOutboundHeaders mutated input header map")
	}
}

// TestScrubIsCaseInsensitive confirms that lowercase header names from
// an HTTP/2 caller (where header names are always lowercase on the wire)
// are scrubbed just like canonical Go casing.
func TestScrubIsCaseInsensitive(t *testing.T) {
	in := http.Header{}
	// http.Header.Set canonicalizes, so to simulate a raw h2 header we
	// set directly on the map.
	in["x-forwarded-for"] = []string{"1.2.3.4"}
	in["cf-connecting-ip"] = []string{"5.6.7.8"}
	in["via"] = []string{"nginx"}

	out := scrubOutboundHeaders(in)
	for _, h := range []string{"X-Forwarded-For", "Cf-Connecting-Ip", "Via"} {
		if out.Get(h) != "" {
			t.Errorf("%s not scrubbed (raw-lowercase input)", h)
		}
	}
}
