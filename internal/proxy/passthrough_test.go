package proxy

import (
	"net/http"
	"testing"
)

// Passthrough must keep the forced UA/sec-ch-ua (TLS↔UA coherence) but NOT
// inject the browser-document soft defaults (Accept:text/html, Sec-Fetch-*),
// and must preserve the caller's own headers — that's what stops JSON API
// gateways (YTJ) from 502ing.
func TestPassthroughSkipsSoftDefaults(t *testing.T) {
	p := SelectProfile(DefaultProfile)

	h := http.Header{}
	h.Set("Accept", "application/json")
	h.Set("X-Requested-With", "XMLHttpRequest")
	applyForcedProfileHeaders(h, p)

	if h.Get("User-Agent") != p.UserAgent {
		t.Errorf("passthrough dropped forced User-Agent")
	}
	if h.Get("sec-ch-ua") != p.SecChUa {
		t.Errorf("passthrough dropped forced sec-ch-ua")
	}
	if got := h.Get("Accept"); got != "application/json" {
		t.Errorf("passthrough clobbered caller Accept = %q, want application/json", got)
	}
	if h.Get("X-Requested-With") != "XMLHttpRequest" {
		t.Errorf("passthrough dropped caller X-Requested-With")
	}
	for _, k := range []string{"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Upgrade-Insecure-Requests", "Priority"} {
		if h.Get(k) != "" {
			t.Errorf("passthrough injected document-navigation header %s=%q", k, h.Get(k))
		}
	}

	// Contrast: the normal path DOES inject the browser-document soft defaults.
	h2 := http.Header{}
	applyProfileDefaults(h2, p)
	if h2.Get("Sec-Fetch-Mode") == "" || h2.Get("Accept") == "" {
		t.Errorf("normal path failed to inject browser soft defaults")
	}
}
