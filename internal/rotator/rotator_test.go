package rotator

import (
	"net/http"
	"testing"
)

func TestShouldRotate(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		header  http.Header
		want    bool
		wantSub string
	}{
		{"429 always", 429, http.Header{}, true, "429"},
		{"plain 403 no", 403, http.Header{}, false, ""},
		{"plain 403 auth required", 403, http.Header{"Www-Authenticate": {"Basic"}}, false, ""},
		{"403 cf-mitigated", 403, http.Header{"Cf-Mitigated": {"challenge"}}, true, "cf-mitigated"},
		{"403 cloudflare server", 403, http.Header{"Server": {"cloudflare"}}, true, "cloudflare"},
		{"503 cloudflare", 503, http.Header{"Server": {"cloudflare"}}, true, "cloudflare"},
		{"503 nginx no", 503, http.Header{"Server": {"nginx"}}, false, ""},
		{"datadome", 403, http.Header{"X-Datadome": {"blocked"}}, true, "datadome"},
		{"akamai", 403, http.Header{"X-Iinfo": {"foo"}}, true, "akamai"},
		{"sucuri", 403, http.Header{"X-Sucuri-Id": {"bar"}}, true, "sucuri"},
		{"200 never", 200, http.Header{}, false, ""},
		{"404 never", 404, http.Header{}, false, ""},
		{"401 never", 401, http.Header{"Www-Authenticate": {"Bearer"}}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := ShouldRotate(c.status, c.header)
			if got != c.want {
				t.Errorf("ShouldRotate = %v, want %v (reason=%q)", got, c.want, reason)
			}
			if c.wantSub != "" && !contains(reason, c.wantSub) {
				t.Errorf("reason = %q, want substring %q", reason, c.wantSub)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
