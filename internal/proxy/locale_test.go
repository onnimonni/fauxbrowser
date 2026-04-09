package proxy

import (
	"strings"
	"testing"
)

func TestAcceptLanguageForCCTLD(t *testing.T) {
	cases := map[string]string{
		"www.shop.example.fi":    "fi-FI",
		"shop.example.se":   "sv-SE",
		"www.proshop.dk":    "da-DK",
		"www.amazon.de":     "de-DE",
		"store.example.at":  "de-AT",
		"www.cdiscount.fr":  "fr-FR",
		"www.bol.nl":        "nl-NL",
		"www.allegro.pl":    "pl-PL",
		"www.notino.cz":     "cs-CZ",
		"www.emag.ro":       "ro-RO",
		"www.argos.co.uk":   "en-GB",
		"www.example.ie":    "en-IE",
		"www.example.ee":    "et-EE",
		"www.example.lt":    "lt-LT",
		"www.example.lv":    "lv-LV",
		"www.example.no":    "nb-NO",
		"www.example.gr":    "el-GR",
	}
	for hostname, wantPrefix := range cases {
		got := AcceptLanguageForHost(hostname)
		if !strings.HasPrefix(got, wantPrefix) {
			t.Errorf("AcceptLanguageForHost(%q) = %q, want prefix %q", hostname, got, wantPrefix)
		}
		// Should always include en-US as fallback.
		if !strings.Contains(got, "en-US") {
			t.Errorf("AcceptLanguageForHost(%q) = %q, missing en-US fallback", hostname, got)
		}
	}
}

func TestAcceptLanguageForGenericTLD(t *testing.T) {
	// .com / .org / .net / .io should return a random Nordic/Baltic language.
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		got := AcceptLanguageForHost("www.example.com")
		seen[got] = true
		// Must always contain en-US.
		if !strings.Contains(got, "en-US") {
			t.Fatalf("generic TLD missing en-US: %q", got)
		}
		// Must start with a Nordic/Baltic locale.
		validPrefixes := []string{"fi-FI", "sv-SE", "nb-NO", "da-DK", "et-EE", "lt-LT", "lv-LV"}
		found := false
		for _, p := range validPrefixes {
			if strings.HasPrefix(got, p) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("generic TLD got unexpected locale: %q", got)
		}
	}
	// After 100 tries we should have seen at least 2 different values.
	if len(seen) < 2 {
		t.Errorf("expected variety in random selection, got %d unique values", len(seen))
	}
}

func TestExtractTLD(t *testing.T) {
	cases := map[string]string{
		"www.shop.example.fi":         "fi",
		"shop.example.co.uk":     "uk",
		"example.com":            "com",
		"a.b.c.d.de":             "de",
		"localhost":              "",
		"127.0.0.1":              "1", // IP — not a real TLD, but harmless
	}
	for in, want := range cases {
		got := extractTLD(in)
		if got != want {
			t.Errorf("extractTLD(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAllTLDMapEntriesHaveEnUS(t *testing.T) {
	for tld, val := range tldAcceptLanguage {
		if !strings.Contains(val, "en-US") {
			t.Errorf("TLD %q Accept-Language %q missing en-US fallback", tld, val)
		}
	}
}
