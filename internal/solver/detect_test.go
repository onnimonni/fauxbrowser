package solver

import (
	"net/http"
	"testing"
)

func TestDetectChallenge(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header http.Header
		want   ChallengeKind
	}{
		{"plain 200", 200, http.Header{}, NotChallenged},
		{"plain 403 no marker", 403, http.Header{}, NotChallenged},
		{"plain 429 no marker", 429, http.Header{}, NotChallenged},

		{"cf-mitigated", 403, http.Header{"Cf-Mitigated": {"challenge"}}, CloudflareChallenge},
		{"cf server 403", 403, http.Header{"Server": {"cloudflare"}}, CloudflareChallenge},
		{"cf server 503", 503, http.Header{"Server": {"cloudflare"}}, CloudflareChallenge},
		{"cf server 429", 429, http.Header{"Server": {"cloudflare"}}, CloudflareChallenge},
		{"cf server 200 — not challenge", 200, http.Header{"Server": {"cloudflare"}}, NotChallenged},

		{"akamai server 403", 403, http.Header{"Server": {"AkamaiGHost"}}, AkamaiChallenge},
		{"akamai abck challenge cookie", 200, http.Header{"Set-Cookie": {"_abck=ABCD~-1~junk; Path=/"}}, AkamaiChallenge},

		{"datadome x-datadome", 403, http.Header{"X-Datadome": {"blocked"}}, DataDomeChallenge},
		{"datadome captcha-delivery redirect", 302, http.Header{"Location": {"https://geo.captcha-delivery.com/captcha/?initialCid=ABC"}}, DataDomeChallenge},

		{"perimeterx _px3 cookie + 403", 403, http.Header{"Set-Cookie": {"_px3=blah; Path=/"}}, PerimeterXChallenge},
		{"perimeterx x-px-action", 403, http.Header{"X-Px-Action": {"block"}}, PerimeterXChallenge},

		{"imperva visid_incap + 403", 403, http.Header{"Set-Cookie": {"visid_incap_12345=junk; Path=/"}}, ImpervaChallenge},

		{"sucuri x-sucuri-id", 403, http.Header{"X-Sucuri-Id": {"blocked"}}, SucuriChallenge},

		{"vercel x-vercel-mitigated challenge", 429, http.Header{"X-Vercel-Mitigated": {"challenge"}, "Server": {"Vercel"}}, VercelChallenge},
		{"vercel x-vercel-challenge-token", 429, http.Header{"X-Vercel-Challenge-Token": {"2.1776149.abc"}}, VercelChallenge},
		{"vercel server 429", 429, http.Header{"Server": {"Vercel"}}, VercelChallenge},
		{"vercel server 200 — not challenge", 200, http.Header{"Server": {"Vercel"}}, NotChallenged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DetectChallenge(c.status, c.header)
			if got != c.want {
				t.Errorf("DetectChallenge = %v, want %v", got, c.want)
			}
		})
	}
}

func TestChallengeKindSolvable(t *testing.T) {
	solvable := []ChallengeKind{
		CloudflareChallenge, AkamaiChallenge, DataDomeChallenge,
		PerimeterXChallenge, ImpervaChallenge, VercelChallenge,
	}
	for _, k := range solvable {
		if !k.Solvable() {
			t.Errorf("%v should be solvable", k)
		}
	}
	notSolvable := []ChallengeKind{NotChallenged, SucuriChallenge}
	for _, k := range notSolvable {
		if k.Solvable() {
			t.Errorf("%v should NOT be solvable (header-only)", k)
		}
	}
}
