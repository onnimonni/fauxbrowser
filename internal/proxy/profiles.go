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
	utls "github.com/bogdanfinn/utls"

	"github.com/onnimonni/fauxbrowser/internal/proxy/fingerprints"
)

// chrome146Captured is a tls-client ClientProfile whose TLS
// ClientHello is sourced from internal/proxy/fingerprints/chrome146.clienthello.hex
// — captured from a real chromium 146 binary via `cmd/capture-fingerprint`.
//
// Its HTTP/2 fingerprint (SETTINGS frame, pseudo-header order,
// connection flow, priorities, HPACK config) is inherited from
// bogdanfinn/tls-client's built-in `profiles.Chrome_146`. That h2
// fingerprint is relatively stable across Chrome versions; the TLS
// ClientHello is not, and was shown to drift by exactly one
// extension between bogdanfinn's Chrome_146 snapshot and real
// chromium 146 (see the tls_fingerprint_ci JA4 test evidence).
//
// We use bogdanfinn/utls's `ClientHelloID.SpecFactory` escape hatch
// to inject our own `ClientHelloSpec` — tls-client dispatches to
// SpecFactory when Client == "Custom" or when SpecFactory is non-nil,
// bypassing the built-in profile table entirely.
//
// Regenerate the hex file with:
//
//	go run ./cmd/capture-fingerprint \
//	    -out internal/proxy/fingerprints/chrome146.clienthello.hex
var chrome146Captured = func() profiles.ClientProfile {
	base := profiles.Chrome_146
	customID := utls.ClientHelloID{
		Client:  "Chrome146Captured",
		Version: "custom",
		SpecFactory: func() (utls.ClientHelloSpec, error) {
			spec, err := fingerprints.Chrome146()
			if err != nil {
				return utls.ClientHelloSpec{}, err
			}
			return *spec, nil
		},
	}
	return profiles.NewClientProfile(
		customID,
		base.GetSettings(),
		base.GetSettingsOrder(),
		base.GetPseudoHeaderOrder(),
		base.GetConnectionFlow(),
		base.GetPriorities(),
		base.GetHeaderPriority(),
		base.GetStreamID(),
		base.GetAllowHTTP(),
		base.GetHttp3Settings(),
		base.GetHttp3SettingsOrder(),
		base.GetHttp3PriorityParam(),
		base.GetHttp3PseudoHeaderOrder(),
		base.GetHttp3SendGreaseFrames(),
	)
}()

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
		TLSProfile: chrome146Captured,
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

// SelectProfileForMajor returns the profile entry whose Major matches
// the given Chrome major version, plus ok=true. When no profile in the
// table matches, returns the zero BrowserProfile and ok=false.
//
// Used by fauxbrowser to auto-align the tls-client fingerprint with
// whatever Chromium the chromedp solver is going to launch — so both
// paths present the same Chrome major version to the origin.
func SelectProfileForMajor(major int) (BrowserProfile, bool) {
	for _, p := range profileTable {
		if p.Major == major {
			return p, true
		}
	}
	return BrowserProfile{}, false
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
