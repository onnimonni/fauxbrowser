package solver

import (
	"net/http"
	"strings"
)

// ChallengeKind names a recognized WAF challenge response type.
type ChallengeKind int

const (
	// NotChallenged is the default zero value.
	NotChallenged ChallengeKind = iota

	// CloudflareChallenge covers IUAM ("Just a moment..."),
	// Turnstile, and managed challenge. They all set cf_clearance
	// once solved.
	CloudflareChallenge

	// AkamaiChallenge is Akamai Bot Manager (the "_abck" cookie
	// flow). Most major US/EU retail sites.
	AkamaiChallenge

	// DataDomeChallenge is DataDome's bot wall. Used by RyanAir,
	// Hermès, Allegro, and many others.
	DataDomeChallenge

	// PerimeterXChallenge is HUMAN Security / PerimeterX (cookies
	// _px3 / _pxhd). Used by Vinted, StubHub, SoFi.
	PerimeterXChallenge

	// ImpervaChallenge is Imperva / Incapsula (cookies
	// visid_incap_*). Less common in 2026.
	ImpervaChallenge

	// SucuriChallenge is the Sucuri firewall. Light WAF, mostly
	// header-based.
	SucuriChallenge

	// VercelChallenge is Vercel's built-in bot protection. Responds
	// with X-Vercel-Mitigated: challenge and X-Vercel-Challenge-Token.
	// Requires a real browser (JavaScript execution) to pass.
	VercelChallenge
)

// String returns a stable identifier for logging.
func (k ChallengeKind) String() string {
	switch k {
	case CloudflareChallenge:
		return "cloudflare"
	case AkamaiChallenge:
		return "akamai"
	case DataDomeChallenge:
		return "datadome"
	case PerimeterXChallenge:
		return "perimeterx"
	case ImpervaChallenge:
		return "imperva"
	case SucuriChallenge:
		return "sucuri"
	case VercelChallenge:
		return "vercel"
	default:
		return "none"
	}
}

// DetectChallenge inspects an upstream response (status code +
// headers only — no body read) and identifies which WAF, if any,
// challenged the request. Body inspection is intentionally avoided
// here so detection stays cheap and never consumes the response
// body the caller wants to forward.
//
// Returns NotChallenged for any response that doesn't match a
// known challenge fingerprint. The caller is responsible for
// deciding whether to dispatch a solver based on the kind.
func DetectChallenge(status int, h http.Header) ChallengeKind {
	// Cloudflare: cf-mitigated, server: cloudflare with 4xx/5xx,
	// or any cf-* header on a non-2xx.
	if v := h.Get("cf-mitigated"); v != "" {
		return CloudflareChallenge
	}
	server := strings.ToLower(h.Get("server"))
	if strings.Contains(server, "cloudflare") && (status == 403 || status == 503 || status == 429) {
		return CloudflareChallenge
	}

	// Akamai: x-akamai-* headers, or server: akamai, or
	// Set-Cookie containing _abck=...~-1~ (the "challenge in
	// progress" sentinel).
	if strings.Contains(server, "akamaighost") || strings.Contains(server, "akamai") {
		if status == 403 || status == 429 {
			return AkamaiChallenge
		}
	}
	for _, sc := range h.Values("Set-Cookie") {
		if strings.Contains(sc, "_abck=") && strings.Contains(sc, "~-1~") {
			return AkamaiChallenge
		}
	}
	if h.Get("x-iinfo") != "" {
		return AkamaiChallenge
	}

	// DataDome: x-datadome / x-dd-b headers, or a redirect to
	// captcha-delivery.com.
	if h.Get("x-datadome") != "" || h.Get("x-dd-b") != "" {
		return DataDomeChallenge
	}
	if loc := h.Get("location"); strings.Contains(loc, "captcha-delivery.com") || strings.Contains(loc, "geo.captcha-delivery.com") {
		return DataDomeChallenge
	}

	// PerimeterX: _px* cookies on a 403, or x-px-* headers.
	if strings.HasPrefix(h.Get("x-px-block"), "1") || h.Get("x-px-action") != "" {
		return PerimeterXChallenge
	}
	for _, sc := range h.Values("Set-Cookie") {
		if strings.HasPrefix(sc, "_px3=") || strings.HasPrefix(sc, "_pxhd=") {
			if status == 403 || status == 429 {
				return PerimeterXChallenge
			}
		}
	}

	// Imperva / Incapsula: visid_incap_* cookie + 4xx, or
	// X-Iinfo header (also Akamai uses x-iinfo, so we tried Akamai
	// first above).
	for _, sc := range h.Values("Set-Cookie") {
		if strings.HasPrefix(sc, "visid_incap_") || strings.HasPrefix(sc, "incap_ses_") {
			if status == 403 || status == 429 {
				return ImpervaChallenge
			}
		}
	}

	// Sucuri: x-sucuri-id header is set by their firewall.
	if h.Get("x-sucuri-id") != "" || h.Get("x-sucuri-block") != "" {
		return SucuriChallenge
	}

	// Vercel: X-Vercel-Mitigated: challenge or X-Vercel-Challenge-Token present.
	if strings.EqualFold(h.Get("x-vercel-mitigated"), "challenge") || h.Get("x-vercel-challenge-token") != "" {
		return VercelChallenge
	}
	// Vercel also serves its checkpoint via server: Vercel with 429.
	if strings.EqualFold(server, "vercel") && status == 429 {
		return VercelChallenge
	}

	return NotChallenged
}

// Solvable reports whether a real browser is likely to be able to
// solve this challenge kind. Sucuri is mostly header-based and
// doesn't need a browser; the others all require JavaScript
// execution.
func (k ChallengeKind) Solvable() bool {
	switch k {
	case CloudflareChallenge, AkamaiChallenge, DataDomeChallenge,
		PerimeterXChallenge, ImpervaChallenge, VercelChallenge:
		return true
	default:
		return false
	}
}
