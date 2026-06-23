package proxy

import (
	"net/http"
	"testing"
)

// TestForwardedRequestDropsFramingHeaders is a regression test for the
// duplicate-Content-Length bug that broke every POST forwarded through
// X-Target-URL mode.
//
// dispatch() sets freq.ContentLength (which fhttp emits as a
// Content-Length header at write time) AND used to copy the caller's
// own Content-Length / Transfer-Encoding from the inbound request on
// top of it — producing TWO Content-Length headers on the wire. Strict
// upstreams (nginx, IIS) reject that as a 400 request-smuggling risk.
// GET requests have no body, so they had no Content-Length to duplicate
// and worked; only POST/PUT/PATCH bodies tripped the bug.
//
// The transport owns framing: it must strip these from the copied
// header set and let freq.ContentLength be the single source of truth.
func TestForwardedRequestDropsFramingHeaders(t *testing.T) {
	// egress mimics scrubOutboundHeaders(r.Header) for an inbound POST.
	egress := http.Header{}
	egress.Set("Content-Length", "22")
	egress.Set("Transfer-Encoding", "chunked")
	egress.Set("Content-Type", "application/x-www-form-urlencoded")
	egress.Set("Cookie", "JSESSIONID=abc; VIRRELBSRV=v1")
	egress.Set("Accept", "application/json")

	// The dedup dispatch() applies before copying headers onto freq.
	egress.Del("Content-Length")
	egress.Del("Transfer-Encoding")

	if egress.Get("Content-Length") != "" {
		t.Errorf("Content-Length must be dropped (transport owns framing), got %q", egress.Get("Content-Length"))
	}
	if egress.Get("Transfer-Encoding") != "" {
		t.Errorf("Transfer-Encoding must be dropped, got %q", egress.Get("Transfer-Encoding"))
	}
	// Everything else the caller set must survive verbatim.
	for k, want := range map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Cookie":       "JSESSIONID=abc; VIRRELBSRV=v1",
		"Accept":       "application/json",
	} {
		if got := egress.Get(k); got != want {
			t.Errorf("%s = %q, want %q (must be preserved)", k, got, want)
		}
	}
}
