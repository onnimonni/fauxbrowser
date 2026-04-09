// Browser profile table + coherent (TLS fingerprint, User-Agent,
// Client-Hints) bundle selection.
//
// Every entry pins the three things that MUST agree on the wire for a
// request to pass a modern WAF's coherence check:
//
//  1. tls-client TLS fingerprint (JA3/JA4)
//  2. Top-level User-Agent string (Chrome major version number)
//  3. Client-Hints sec-ch-ua bundle (same major version)
//
// A mismatch between (1) and (2)/(3) is the "ghost Chrome 87" failure
// mode that triggered the v0.4 UA-forcing fix; keeping them as a single
// struct here makes the invariant impossible to break accidentally.
// profiles_test.go asserts the invariant at test time so an entry with
// a mismatched version number fails CI.
package proxy

import (
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
)

// BrowserProfile bundles a TLS fingerprint with the matching
// application-layer headers.
type BrowserProfile struct {
	Name       string                 // e.g. "chrome146"
	Major      int                    // e.g. 146
	TLSProfile profiles.ClientProfile // tls-client fingerprint
	UserAgent  string
	SecChUa    string // `"Chromium";v="146", ...`
	SecChUaMob string // "?0" (desktop) or "?1" (mobile)
	Platform   string // `"macOS"`, `"Windows"`, `"Linux"`
}

// DefaultProfile is what fauxbrowser falls back to when no flag is set.
// Bump this (and add a new table entry) when a newer Chrome fingerprint
// ships in bogdanfinn/tls-client.
const DefaultProfile = "chrome146"

// LatestAlias resolves to DefaultProfile. Kept as a separate string so
// a downstream config can say "always use latest" without being pinned
// to a specific version.
const LatestAlias = "latest"

// profileTable is the supported set. To add Chrome N:
//  1. Verify profiles.Chrome_N exists in bogdanfinn/tls-client.
//  2. Add an entry below with matching Major, UserAgent, SecChUa.
//  3. profiles_test.go#TestProfileCoherence will verify the three
//     version strings agree.
var profileTable = map[string]BrowserProfile{
	"chrome146": {
		Name:       "chrome146",
		Major:      146,
		TLSProfile: profiles.Chrome_146,
		UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:    `"Chromium";v="146", "Not.A/Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMob: "?0",
		Platform:   `"macOS"`,
	},
	"chrome144": {
		Name:       "chrome144",
		Major:      144,
		TLSProfile: profiles.Chrome_144,
		UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:    `"Chromium";v="144", "Not.A/Brand";v="24", "Google Chrome";v="144"`,
		SecChUaMob: "?0",
		Platform:   `"macOS"`,
	},
	"chrome133": {
		Name:       "chrome133",
		Major:      133,
		TLSProfile: profiles.Chrome_133,
		UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		SecChUa:    `"Chromium";v="133", "Not.A/Brand";v="24", "Google Chrome";v="133"`,
		SecChUaMob: "?0",
		Platform:   `"macOS"`,
	},
	"chrome131": {
		Name:       "chrome131",
		Major:      131,
		TLSProfile: profiles.Chrome_131,
		UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecChUa:    `"Chromium";v="131", "Not.A/Brand";v="24", "Google Chrome";v="131"`,
		SecChUaMob: "?0",
		Platform:   `"macOS"`,
	},
}

// SelectProfile resolves a (possibly empty, possibly "latest") profile
// name to a BrowserProfile. Unknown names log a warning and fall back
// to the default — unit tests catch typos via TestUnknownProfileFallback.
func SelectProfile(name string) BrowserProfile {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" || key == LatestAlias {
		key = DefaultProfile
	}
	p, ok := profileTable[key]
	if !ok {
		slog.Warn("unknown browser profile, falling back",
			"requested", name, "using", DefaultProfile)
		return profileTable[DefaultProfile]
	}
	return p
}

// KnownProfiles returns the sorted list of profile names.
func KnownProfiles() []string {
	out := make([]string, 0, len(profileTable))
	for k := range profileTable {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// applyProfileDefaults forces the coherence-critical headers from the
// selected profile (User-Agent, sec-ch-ua*), and fills in the caller-
// overridable soft defaults (Accept, Accept-Language, etc.) only when
// the caller didn't set them.
//
// Why "force" vs "default-if-empty":
//   - UA + sec-ch-ua bundle MUST agree with the TLS fingerprint, so we
//     always overwrite these. Letting a caller set a different UA would
//     desynchronize the wire-level fingerprint from the app-level one.
//   - Accept / Accept-Language / Sec-Fetch-* are semantically per-request
//     and safe for the caller to override.
func applyProfileDefaults(h http.Header, p BrowserProfile) http.Header {
	// Forced: always overwrite.
	h.Del("User-Agent")
	h.Set("User-Agent", p.UserAgent)
	h.Del("sec-ch-ua")
	h.Set("sec-ch-ua", p.SecChUa)
	h.Del("sec-ch-ua-mobile")
	h.Set("sec-ch-ua-mobile", p.SecChUaMob)
	h.Del("sec-ch-ua-platform")
	h.Set("sec-ch-ua-platform", p.Platform)

	// Soft: fill if missing.
	for k, v := range softDefaults {
		if h.Get(k) == "" {
			h.Set(k, v)
		}
	}
	return h
}

// softDefaults are caller-overridable browser-plausible headers.
var softDefaults = map[string]string{
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"Accept-Language":           "en-US,en;q=0.9",
	"Accept-Encoding":           "gzip, deflate, br, zstd",
	"Upgrade-Insecure-Requests": "1",
	"Sec-Fetch-Dest":            "document",
	"Sec-Fetch-Mode":            "navigate",
	"Sec-Fetch-Site":            "none",
	"Sec-Fetch-User":            "?1",
}
