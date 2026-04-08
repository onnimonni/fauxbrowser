// Package config holds fauxbrowser's runtime configuration.
package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Listen       string
	AdminListen  string
	Upstream     string
	Profile      string
	CACertPath   string
	CAKeyPath    string
	CAOut        string
	TargetHeader string
	ProfileHdr   string
	SessionHdr   string
	TimeoutSecs  int
	Auth         string   // "user:pass" for Proxy-Authorization Basic
	AllowHosts   []string // glob list; empty = allow all
	AllowOpen    bool     // allow non-loopback listen without auth
	LeafCacheMax int
	SessionMax   int
	Insecure     bool // skip TLS verify on upstream (tests only)
	LogLevel     string
}

func Default() *Config {
	return &Config{
		Listen:       "127.0.0.1:18443",
		Profile:      "chrome146",
		TargetHeader: "X-Target-URL",
		ProfileHdr:   "X-Fauxbrowser-Profile",
		SessionHdr:   "X-Fauxbrowser-Session",
		TimeoutSecs:  60,
		LeafCacheMax: 1024,
		SessionMax:   256,
		LogLevel:     "info",
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
	if v := os.Getenv("FAUXBROWSER_UPSTREAM"); v != "" {
		c.Upstream = v
	}
	if v := os.Getenv("FAUXBROWSER_PROFILE"); v != "" {
		c.Profile = v
	}
	if v := os.Getenv("FAUXBROWSER_CA_CERT"); v != "" {
		c.CACertPath = v
	}
	if v := os.Getenv("FAUXBROWSER_CA_KEY"); v != "" {
		c.CAKeyPath = v
	}
	if v := os.Getenv("FAUXBROWSER_CA_OUT"); v != "" {
		c.CAOut = v
	}
	if v := os.Getenv("FAUXBROWSER_AUTH"); v != "" {
		c.Auth = v
	}
	if v := os.Getenv("FAUXBROWSER_ALLOW_HOSTS"); v != "" {
		c.AllowHosts = SplitCSV(v)
	}
	if v := os.Getenv("FAUXBROWSER_ALLOW_OPEN"); v == "1" || v == "true" {
		c.AllowOpen = true
	}
	if v := os.Getenv("FAUXBROWSER_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.TimeoutSecs = n
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
