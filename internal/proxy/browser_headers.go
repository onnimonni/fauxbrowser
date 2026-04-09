package proxy

import (
	"net/http"
	"strings"
)

// defaultBrowserHeaders returns a minimal set of headers that a matching
// browser would send on a top-level navigation. Only headers the caller
// has NOT set are filled in, so application-specific overrides are kept.
//
// These headers must be kept in sync with the TLS profile family selected
// by the caller. Anything more elaborate (sec-ch-ua, sec-fetch-*) is
// omitted to stay compatible with non-navigation requests.
func defaultBrowserHeaders(profile string) http.Header {
	p := strings.ToLower(profile)
	switch {
	case strings.HasPrefix(p, "chrome"):
		return http.Header{
			"User-Agent": {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"},
			"Accept":     {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			"Accept-Language": {"en-US,en;q=0.9"},
			"Accept-Encoding": {"gzip, deflate, br, zstd"},
		}
	case strings.HasPrefix(p, "firefox"):
		return http.Header{
			"User-Agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:147.0) Gecko/20100101 Firefox/147.0"},
			"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
			"Accept-Language": {"en-US,en;q=0.5"},
			"Accept-Encoding": {"gzip, deflate, br, zstd"},
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

// applyDefaults fills in browser defaults for headers the caller has not set.
// Curl's default User-Agent ("curl/8.x") is treated as unset.
func applyDefaults(existing http.Header, profile string) http.Header {
	defaults := defaultBrowserHeaders(profile)
	if defaults == nil {
		return existing
	}
	out := existing
	for k, vs := range defaults {
		cur := out.Get(k)
		if cur == "" || (k == "User-Agent" && strings.HasPrefix(strings.ToLower(cur), "curl/")) {
			out.Del(k)
			for _, v := range vs {
				out.Add(k, v)
			}
		}
	}
	return out
}
