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
	// Proton catalog.
	WGConf string

	// Proton server filter.
	VPNTier       string   // "free" (default), "paid"/"plus", "all"
	VPNCountries  []string // ISO alpha-2
	VPNContinents []string // EU, NA, AS, ...

	// Browser profile used for TLS fingerprint + header bundle.
	// Empty or "latest" = chrome146 (the current default). Known
	// values: chrome146, chrome144, chrome133, chrome131.
	Profile string

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
	if v := os.Getenv("FAUXBROWSER_WG_CONF"); v != "" {
		c.WGConf = v
	}
	if v := os.Getenv("FAUXBROWSER_VPN_TIER"); v != "" {
		c.VPNTier = v
	}
	if v := os.Getenv("FAUXBROWSER_PROFILE"); v != "" {
		c.Profile = v
	}
	if v := os.Getenv("FAUXBROWSER_VPN_COUNTRIES"); v != "" {
		c.VPNCountries = SplitCSV(v)
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
