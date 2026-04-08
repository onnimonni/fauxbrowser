package config

import (
	"os"
	"reflect"
	"testing"
)

func TestResolveCountryNames(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, []string{}},
		{[]string{"NL", "DE"}, []string{"NL", "DE"}},
		{[]string{"nl"}, []string{"NL"}},
		{[]string{"Netherlands"}, []string{"NL"}},
		{[]string{"netherlands"}, []string{"NL"}},
		{[]string{"Netherlands", "Germany", "JP"}, []string{"NL", "DE", "JP"}},
		{[]string{"USA", "Canada"}, []string{"US", "CA"}},
		{[]string{"United States", "United Kingdom"}, []string{"US", "GB"}},
		{[]string{"Atlantis"}, []string{}},                                  // unknown name → dropped
		{[]string{"NL", "Atlantis", "Germany"}, []string{"NL", "DE"}},
	}
	for _, c := range cases {
		got := ResolveCountryNames(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ResolveCountryNames(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLoadEnvGluetunAliases(t *testing.T) {
	t.Setenv("WIREGUARD_PRIVATE_KEY", "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=")
	t.Setenv("SERVER_COUNTRIES", "Netherlands,Germany,jp")
	t.Setenv("FREE_ONLY", "on")

	c := Default()
	c.LoadEnv()

	if c.WGPrivateKey != "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=" {
		t.Errorf("WGPrivateKey = %q", c.WGPrivateKey)
	}
	if want := []string{"NL", "DE", "JP"}; !reflect.DeepEqual(c.VPNCountries, want) {
		t.Errorf("VPNCountries = %v, want %v", c.VPNCountries, want)
	}
	if c.VPNTier != "free" {
		t.Errorf("VPNTier = %q, want free", c.VPNTier)
	}
}

func TestLoadEnvNativeOverridesGluetun(t *testing.T) {
	// FAUXBROWSER_VPN_COUNTRIES is processed BEFORE SERVER_COUNTRIES
	// in LoadEnv, so SERVER_COUNTRIES wins when both are set. That's
	// the expected priority: gluetun-compat aliases override native
	// envs because they're applied later.
	t.Setenv("FAUXBROWSER_VPN_COUNTRIES", "NL")
	t.Setenv("SERVER_COUNTRIES", "Germany")
	c := Default()
	c.LoadEnv()
	if !reflect.DeepEqual(c.VPNCountries, []string{"DE"}) {
		t.Errorf("VPNCountries = %v, want [DE] (SERVER_COUNTRIES should win)", c.VPNCountries)
	}
}

func TestLoadEnvFreeOnlyVariants(t *testing.T) {
	cases := map[string]string{
		"on":    "free",
		"true":  "free",
		"1":     "free",
		"yes":   "free",
		// "off" / "false" / "0" / "no" should NOT change tier from default.
	}
	for v, wantTier := range cases {
		t.Run(v, func(t *testing.T) {
			os.Unsetenv("FAUXBROWSER_VPN_TIER")
			t.Setenv("FREE_ONLY", v)
			c := Default()
			c.LoadEnv()
			if c.VPNTier != wantTier {
				t.Errorf("FREE_ONLY=%q → VPNTier=%q, want %q", v, c.VPNTier, wantTier)
			}
		})
	}
}
