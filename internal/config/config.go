// Package config holds fauxbrowser's runtime configuration.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen       string
	AdminListen  string
	TargetHeader string

	// Bearer tokens for the proxy and admin listeners. Empty = disabled
	// (which is only permitted on loopback; see main.safetyCheck).
	AuthToken  string
	AdminToken string

	// WireGuard base conf: private key, interface address, DNS, MTU.
	// Peer fields are ignored — the rotator supplies them from the
	// Proton catalog. Provide EITHER WGConf (path to a wg-quick .conf)
	// OR WGPrivateKey (just the base64 private key, gluetun-style).
	WGConf       string
	WGPrivateKey string

	// Proton server filter.
	VPNTier       string   // "free" (default), "paid"/"plus", "all"
	VPNCountries  []string // ISO alpha-2
	VPNContinents []string // EU, NA, AS, ...

	// Browser profile used for TLS fingerprint + header bundle.
	// Empty or "latest" = chrome146 (the current default). Known
	// values: chrome146, chrome144, chrome133, chrome131.
	Profile string

	// WAF challenge solver. "" / "none" = disabled (no Chromium
	// dependency, the binary is fully self-contained). "chromedp"
	// launches a fresh headless Chromium per solve via chromedp,
	// routes its traffic back through fauxbrowser CONNECT, extracts
	// clearance cookies, and caches them per (host, exit_ip).
	Solver         string        // "none" (default), "chromedp"
	SolverTTL      time.Duration // cookie cache TTL (default 25m)
	SolverTimeout  time.Duration // per-solve browser deadline (default 30s)
	ChromiumPath   string        // override Chromium binary path (default = $PATH lookup)

	// CookieStorePath is an optional file path for persisting the
	// solver's CF cookie cache to disk. When set, the cache is
	// loaded on startup and saved on each VPN rotation + shutdown.
	// Cookies survive process restarts, so solved CF sessions can
	// be reused across deploys without re-solving.
	CookieStorePath string

	// ScoresPath is an optional file path for persisting the pool's
	// per-IP EMA reputation scores to disk. When set, scores are
	// loaded on startup and saved every ~5s (debounced) + on shutdown.
	// Survives process restarts so the pool doesn't start blind.
	ScoresPath string

	// Direct disables WireGuard entirely. All outbound connections
	// go directly through the host's network. The Chrome TLS
	// fingerprint forging, header scrubbing, and WAF solver still
	// apply — only the VPN tunnel is bypassed. Useful for local
	// debugging or for sites where VPN IP reputation causes issues.
	// When Direct=true, WGConf/WGPrivateKey are not required.
	Direct bool

	// AllowVersionMismatch permits fauxbrowser to start when the
	// chromedp solver's Chromium binary has a Chrome major version
	// that disagrees with the active tls-client profile (or has no
	// matching profile at all). False by default — a mismatch means
	// the solver's ClientHello and the fast path's ClientHello use
	// different JA3/JA4 fingerprints, which breaks cookie portability
	// for WAFs that pin cf_clearance to the solving TLS fingerprint.
	// Intended escape hatch for "chromium just got bumped to N+1 and
	// bogdanfinn/tls-client hasn't shipped chromeN+1 yet".
	AllowVersionMismatch bool

	TimeoutSecs   int
	CooldownSecs  int           // taint cooldown per server after 429/403
	HandshakeWait time.Duration // handshake observation window per rotation attempt

	// Blue/green rotator tuning.
	MinHostRotation   time.Duration // per-host debounce window
	GlobalMinInterval time.Duration // global backstop between rotations
	MaxRetireAge      time.Duration // force-close retired tunnels past this age
	ReaperInterval    time.Duration // how often the reaper scans

	LogLevel string
}

func Default() *Config {
	return &Config{
		Listen:        "127.0.0.1:18443",
		TargetHeader:  "X-Target-URL",
		VPNTier:       "free",
		Profile:       "chrome146",
		Solver:        "none",
		SolverTTL:     25 * time.Minute,
		SolverTimeout: 30 * time.Second,
		TimeoutSecs:   60,
		CooldownSecs:      900, // 15 min
		HandshakeWait:     6 * time.Second,
		MinHostRotation:   5 * time.Minute,
		GlobalMinInterval: 2 * time.Second,
		MaxRetireAge:      2 * time.Minute,
		ReaperInterval:    5 * time.Second,
		LogLevel:          "info",
	}
}

// LoadEnv applies env-var overlays. Call before flag.Parse so flags
// still take precedence.
func (c *Config) LoadEnv() {
	if v := os.Getenv("FAUXBROWSER_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("FAUXBROWSER_ADMIN_LISTEN"); v != "" {
		c.AdminListen = v
	}
	if v := os.Getenv("FAUXBROWSER_AUTH_TOKEN"); v != "" {
		c.AuthToken = v
	}
	if v := os.Getenv("FAUXBROWSER_ADMIN_TOKEN"); v != "" {
		c.AdminToken = v
	}
	if v := strings.ToLower(os.Getenv("FAUXBROWSER_DIRECT")); v != "" {
		switch v {
		case "1", "true", "yes", "on":
			c.Direct = true
		}
	}
	if v := os.Getenv("FAUXBROWSER_WG_CONF"); v != "" {
		c.WGConf = v
	}
	if v := os.Getenv("FAUXBROWSER_WG_PRIVATE_KEY"); v != "" {
		c.WGPrivateKey = v
	}
	// Gluetun-compatible alias.
	if v := os.Getenv("WIREGUARD_PRIVATE_KEY"); v != "" {
		c.WGPrivateKey = v
	}
	if v := os.Getenv("FAUXBROWSER_VPN_TIER"); v != "" {
		c.VPNTier = v
	}
	// Gluetun-compatible alias: FREE_ONLY=on/true/1 → tier=free.
	if v := strings.ToLower(os.Getenv("FREE_ONLY")); v != "" {
		switch v {
		case "1", "true", "on", "yes":
			c.VPNTier = "free"
		case "0", "false", "off", "no":
			// Don't restrict tier; let the user pick via VPN_TIER or
			// the default. Leaving as-is is the right behavior.
		}
	}
	if v := os.Getenv("FAUXBROWSER_PROFILE"); v != "" {
		c.Profile = v
	}
	if v := os.Getenv("FAUXBROWSER_SOLVER"); v != "" {
		c.Solver = v
	}
	if v := os.Getenv("FAUXBROWSER_SOLVER_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.SolverTTL = d
		}
	}
	if v := os.Getenv("FAUXBROWSER_SOLVER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.SolverTimeout = d
		}
	}
	if v := os.Getenv("FAUXBROWSER_CHROMIUM_PATH"); v != "" {
		c.ChromiumPath = v
	}
	if v := os.Getenv("FAUXBROWSER_COOKIE_STORE"); v != "" {
		c.CookieStorePath = v
	}
	if v := os.Getenv("FAUXBROWSER_SCORES_PATH"); v != "" {
		c.ScoresPath = v
	}
	if v := strings.ToLower(os.Getenv("FAUXBROWSER_ALLOW_VERSION_MISMATCH")); v != "" {
		switch v {
		case "1", "true", "yes", "on":
			c.AllowVersionMismatch = true
		}
	}
	if v := os.Getenv("FAUXBROWSER_VPN_COUNTRIES"); v != "" {
		c.VPNCountries = SplitCSV(v)
	}
	// Gluetun-compatible alias. Supports both ISO-2 codes ("NL,DE") and
	// country names ("Netherlands,Germany"). Names are translated via
	// the SERVER_COUNTRIES → ISO map.
	if v := os.Getenv("SERVER_COUNTRIES"); v != "" {
		c.VPNCountries = ResolveCountryNames(SplitCSV(v))
	}
	if v := os.Getenv("FAUXBROWSER_VPN_CONTINENTS"); v != "" {
		c.VPNContinents = SplitCSV(v)
	}
	if v := os.Getenv("FAUXBROWSER_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.TimeoutSecs = n
		}
	}
	if v := os.Getenv("FAUXBROWSER_COOLDOWN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.CooldownSecs = n
		}
	}
	if v := os.Getenv("FAUXBROWSER_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
}

// countryNameToISO maps the country names that gluetun's SERVER_COUNTRIES
// env var accepts to their ISO-3166-1 alpha-2 codes. Only the countries
// where Proton actually offers servers are exhaustively listed; the
// rest fall through and any input that already looks like an ISO code
// is passed through verbatim.
var countryNameToISO = map[string]string{
	"netherlands":    "NL",
	"germany":        "DE",
	"switzerland":    "CH",
	"romania":        "RO",
	"japan":          "JP",
	"united states":  "US",
	"usa":            "US",
	"canada":         "CA",
	"mexico":         "MX",
	"singapore":      "SG",
	"norway":         "NO",
	"poland":         "PL",
	"france":         "FR",
	"united kingdom": "GB",
	"uk":             "GB",
	"italy":          "IT",
	"spain":          "ES",
	"sweden":         "SE",
	"finland":        "FI",
	"denmark":        "DK",
	"belgium":        "BE",
	"austria":        "AT",
	"czech republic": "CZ",
	"czechia":        "CZ",
}

// ResolveCountryNames maps a list of country names or ISO codes to a
// list of ISO codes. Two-character entries are passed through (assumed
// to already be ISO codes). Longer entries are looked up in
// countryNameToISO; unknown names are dropped.
func ResolveCountryNames(in []string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if len(s) == 2 {
			out = append(out, strings.ToUpper(s))
			continue
		}
		if iso, ok := countryNameToISO[strings.ToLower(s)]; ok {
			out = append(out, iso)
		}
	}
	return out
}

func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
