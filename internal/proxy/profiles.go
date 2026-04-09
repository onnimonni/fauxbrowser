package proxy

import (
	"log/slog"
	"sort"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
)

// profileTable maps canonical lower-case aliases to tls-client profiles.
// Add entries here when tls-client ships a new fingerprint we care about.
var profileTable = map[string]profiles.ClientProfile{
	"chrome146":       profiles.Chrome_146,
	"chrome144":       profiles.Chrome_144,
	"chrome133":       profiles.Chrome_133,
	"chrome131":       profiles.Chrome_131,
	"chrome124":       profiles.Chrome_124,
	"chrome120":       profiles.Chrome_120,
	"chrome117":       profiles.Chrome_117,
	"firefox147":      profiles.Firefox_147,
	"firefox135":      profiles.Firefox_135,
	"firefox133":      profiles.Firefox_133,
	"firefox123":      profiles.Firefox_123,
	"firefox117":      profiles.Firefox_117,
	"safari16":        profiles.Safari_16_0,
	"safari_ios_18_5": profiles.Safari_IOS_18_5,
	"safari_ios_16_0": profiles.Safari_IOS_16_0,
	"safari_ios_15_5": profiles.Safari_IOS_15_5,
	"opera_90":        profiles.Opera_90,
}

// Aliases shortcut to "latest" per-browser.
var aliases = map[string]string{
	"chrome":  "chrome146",
	"latest":  "chrome146",
	"firefox": "firefox147",
	"safari":  "safari16",
	"opera":   "opera_90",
}

// SelectProfile resolves a name to a tls-client ClientProfile.
// Unknown names fall back to Chrome 146 and emit a warning.
func SelectProfile(name string) profiles.ClientProfile {
	key := strings.ToLower(strings.TrimSpace(name))
	if alias, ok := aliases[key]; ok {
		key = alias
	}
	if p, ok := profileTable[key]; ok {
		return p
	}
	slog.Warn("unknown profile; falling back to chrome146", "requested", name)
	return profiles.Chrome_146
}

// KnownProfiles returns all supported profile names, sorted.
func KnownProfiles() []string {
	out := make([]string, 0, len(profileTable))
	for k := range profileTable {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
