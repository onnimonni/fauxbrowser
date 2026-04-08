package proxy

import (
	"net/http"
	"strings"
)

// defaultBrowserHeaders returns a minimal set of headers that a real browser
// would send on a top-level navigation. Only headers the caller has not set
// are filled in, so application overrides are kept.
//
// The Chrome bundle includes a full Client-Hints (sec-ch-ua*) set — many
// modern sites flag requests with a Chrome User-Agent that's missing
// sec-ch-ua as "outdated browser" (k-ruoka.fi does exactly this), so the
// UA + CH pair must ship together.
//
// These defaults should stay in sync with the TLS profile family selected
// by the caller. The version strings must also match the UA major version
// so Client-Hints parsing on the origin is consistent.
func defaultBrowserHeaders(profile string) http.Header {
	p := strings.ToLower(profile)
	switch {
	case strings.HasPrefix(p, "chrome"):
		return http.Header{
			"User-Agent":                {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
			"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"Accept-Language":           {"en-US,en;q=0.9"},
			"Accept-Encoding":           {"gzip, deflate, br, zstd"},
			"Sec-Ch-Ua":                 {`"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
			"Sec-Ch-Ua-Mobile":          {"?0"},
			"Sec-Ch-Ua-Platform":        {`"macOS"`},
			"Sec-Fetch-Site":            {"none"},
			"Sec-Fetch-Mode":            {"navigate"},
			"Sec-Fetch-User":            {"?1"},
			"Sec-Fetch-Dest":            {"document"},
			"Upgrade-Insecure-Requests": {"1"},
		}
	case strings.HasPrefix(p, "firefox"):
		return http.Header{
			"User-Agent":                {"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:132.0) Gecko/20100101 Firefox/132.0"},
			"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
			"Accept-Language":           {"en-US,en;q=0.5"},
			"Accept-Encoding":           {"gzip, deflate, br, zstd"},
			"Upgrade-Insecure-Requests": {"1"},
			"Sec-Fetch-Dest":            {"document"},
			"Sec-Fetch-Mode":            {"navigate"},
			"Sec-Fetch-Site":            {"none"},
			"Sec-Fetch-User":            {"?1"},
		}
	case strings.HasPrefix(p, "safari_ios"):
		return http.Header{
			"User-Agent":      {"Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"},
			"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			"Accept-Language": {"en-US,en;q=0.9"},
			"Accept-Encoding": {"gzip, deflate, br"},
		}
	case strings.HasPrefix(p, "safari"):
		return http.Header{
			"User-Agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"},
			"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			"Accept-Language": {"en-US,en;q=0.9"},
			"Accept-Encoding": {"gzip, deflate, br"},
		}
	case strings.HasPrefix(p, "opera"):
		return http.Header{
			"User-Agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 OPR/90.0.4480.84"},
			"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			"Accept-Language": {"en-US,en;q=0.9"},
			"Accept-Encoding": {"gzip, deflate, br"},
		}
	default:
		return nil
	}
}

// forcedHeaders are always rewritten to match the active TLS profile.
// They are the "browser fingerprint" bundle — sending a Chrome 131 UA with a
// Chrome 146 TLS handshake desyncs our forgery, so fauxbrowser enforces
// consistency even when the caller tried to override them (this includes
// headers shipped by ~/.curlrc and common crawler defaults).
var forcedHeaders = map[string]struct{}{
	"User-Agent":         {},
	"Sec-Ch-Ua":          {},
	"Sec-Ch-Ua-Mobile":   {},
	"Sec-Ch-Ua-Platform": {},
}

// applyDefaults merges the per-profile browser headers into existing.
// Headers in forcedHeaders are always overwritten with our value. All
// others are filled in only when the caller hasn't set them (or has set
// an obviously-curl default like "*/*").
func applyDefaults(existing http.Header, profile string) http.Header {
	defaults := defaultBrowserHeaders(profile)
	if defaults == nil {
		return existing
	}
	out := existing
	for k, vs := range defaults {
		if _, forced := forcedHeaders[k]; forced {
			out.Del(k)
			for _, v := range vs {
				out.Add(k, v)
			}
			continue
		}
		cur := out.Get(k)
		if cur == "" || isCurlSmell(k, cur) {
			out.Del(k)
			for _, v := range vs {
				out.Add(k, v)
			}
		}
	}
	return out
}

func isCurlSmell(header, value string) bool {
	switch header {
	case "Accept":
		return value == "*/*"
	}
	return false
}
