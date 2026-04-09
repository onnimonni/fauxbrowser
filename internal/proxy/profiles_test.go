package proxy

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestProfileCoherence is the load-bearing invariant test for the
// profile table. Every entry must have its UserAgent and sec-ch-ua
// bundle agree with the Major field AND with the numeric suffix of
// the profile name. A mismatch between (TLS, UA, sec-ch-ua) is the
// exact failure mode this whole system is meant to prevent — if this
// test breaks in CI, the offending profile entry ships a desynced
// fingerprint and would fail Client-Hints validators on real targets.
func TestProfileCoherence(t *testing.T) {
	uaMajorRe := regexp.MustCompile(`Chrome/(\d+)\.`)
	secchuaMajorRe := regexp.MustCompile(`"Google Chrome";v="(\d+)"`)
	nameSuffixRe := regexp.MustCompile(`^chrome(\d+)$`)

	for name, p := range profileTable {
		t.Run(name, func(t *testing.T) {
			if p.Name != name {
				t.Errorf("Name %q != map key %q", p.Name, name)
			}

			m := nameSuffixRe.FindStringSubmatch(name)
			if m == nil {
				t.Fatalf("profile name %q does not match chromeNNN pattern", name)
			}
			suffix, _ := strconv.Atoi(m[1])
			if p.Major != suffix {
				t.Errorf("Major=%d, name suggests %d", p.Major, suffix)
			}

			uaMatch := uaMajorRe.FindStringSubmatch(p.UserAgent)
			if uaMatch == nil {
				t.Fatalf("UserAgent has no Chrome/NN version: %q", p.UserAgent)
			}
			uaMajor, _ := strconv.Atoi(uaMatch[1])
			if uaMajor != p.Major {
				t.Errorf("UserAgent Chrome/%d != Major %d", uaMajor, p.Major)
			}

			scMatch := secchuaMajorRe.FindStringSubmatch(p.SecChUa)
			if scMatch == nil {
				t.Fatalf("SecChUa has no Google Chrome;v=NN: %q", p.SecChUa)
			}
			scMajor, _ := strconv.Atoi(scMatch[1])
			if scMajor != p.Major {
				t.Errorf("SecChUa Google Chrome;v=%d != Major %d", scMajor, p.Major)
			}
			// Chromium;vN should also agree.
			if !strings.Contains(p.SecChUa, fmt.Sprintf(`"Chromium";v="%d"`, p.Major)) {
				t.Errorf("SecChUa missing Chromium;v=%d: %q", p.Major, p.SecChUa)
			}
		})
	}
}

func TestSelectProfileDefault(t *testing.T) {
	cases := []string{"", "latest", "LATEST", "  "}
	for _, in := range cases {
		p := SelectProfile(in)
		if p.Name != DefaultProfile {
			t.Errorf("SelectProfile(%q) = %q, want %q", in, p.Name, DefaultProfile)
		}
	}
}

func TestSelectProfileKnown(t *testing.T) {
	for _, name := range KnownProfiles() {
		p := SelectProfile(name)
		if p.Name != name {
			t.Errorf("SelectProfile(%q).Name = %q", name, p.Name)
		}
	}
	// Case insensitivity.
	if SelectProfile("CHROME146").Name != "chrome146" {
		t.Errorf("SelectProfile is not case-insensitive")
	}
}

func TestSelectProfileUnknownFallsBack(t *testing.T) {
	p := SelectProfile("firefox999")
	if p.Name != DefaultProfile {
		t.Errorf("unknown profile should fall back to %q, got %q", DefaultProfile, p.Name)
	}
}

func TestApplyProfileDefaultsForces(t *testing.T) {
	h := http.Header{}
	// Caller pre-sets a WRONG UA; profile must overwrite it.
	h.Set("User-Agent", "SomeCustomBot/1.0")
	h.Set("sec-ch-ua", `"NotReal";v="1"`)

	p := SelectProfile("chrome144")
	out := applyProfileDefaults(h, p)

	if out.Get("User-Agent") != p.UserAgent {
		t.Errorf("User-Agent not forced to profile: got %q want %q", out.Get("User-Agent"), p.UserAgent)
	}
	if out.Get("sec-ch-ua") != p.SecChUa {
		t.Errorf("sec-ch-ua not forced: got %q want %q", out.Get("sec-ch-ua"), p.SecChUa)
	}
	if out.Get("sec-ch-ua-mobile") != p.SecChUaMob {
		t.Errorf("sec-ch-ua-mobile not forced")
	}
	if out.Get("sec-ch-ua-platform") != p.Platform {
		t.Errorf("sec-ch-ua-platform not forced")
	}
}

func TestApplyProfileDefaultsPreservesCallerSoftHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Accept-Language", "fi-FI,fi;q=0.9")
	h.Set("Accept", "application/json")
	p := SelectProfile("chrome146")
	out := applyProfileDefaults(h, p)

	if got := out.Get("Accept-Language"); got != "fi-FI,fi;q=0.9" {
		t.Errorf("Accept-Language was overwritten: %q", got)
	}
	if got := out.Get("Accept"); got != "application/json" {
		t.Errorf("Accept was overwritten: %q", got)
	}
	// And the unset soft ones should have been filled.
	if out.Get("Sec-Fetch-Mode") == "" {
		t.Errorf("Sec-Fetch-Mode should have been set from softDefaults")
	}
}

// TestChromeHeaderOrderMatchesCapture verifies the pinned header
// order matches what was captured from real Chrome 146 via
// tls.peet.ws/api/all on 2026-04-09. If Chrome bumps to a new
// version with different header ordering, this test will need
// updating alongside the profile.
func TestChromeHeaderOrderMatchesCapture(t *testing.T) {
	// Expected order captured from Chrome 146.0.7680.178 on macOS.
	// The order is Chrome's internal decision — it comes from the
	// browser's renderer attaching headers in a specific sequence.
	want := []string{
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept-language",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"accept-encoding",
		"priority",
		"cookie",
	}
	if len(chromeHeaderOrder) != len(want) {
		t.Fatalf("chromeHeaderOrder has %d entries, want %d", len(chromeHeaderOrder), len(want))
	}
	for i, got := range chromeHeaderOrder {
		if got != want[i] {
			t.Errorf("chromeHeaderOrder[%d] = %q, want %q", i, got, want[i])
		}
	}
}

// TestSoftDefaultsIncludeAllChromeHeaders verifies every non-forced
// header in the Chrome order has a soft default, so a bare request
// with no caller-set headers still looks like a real Chrome
// navigation.
func TestSoftDefaultsIncludeAllChromeHeaders(t *testing.T) {
	// These headers are forced (not soft defaults) or are set
	// by the caller (cookie) — skip them in this check.
	forced := map[string]bool{
		"sec-ch-ua":          true,
		"sec-ch-ua-mobile":   true,
		"sec-ch-ua-platform": true,
		"user-agent":         true,
		"cookie":             true,
	}
	for _, h := range chromeHeaderOrder {
		if forced[h] {
			continue
		}
		if _, ok := softDefaults[canonicalSoftKey(h)]; !ok {
			t.Errorf("chromeHeaderOrder includes %q but softDefaults has no entry for it", h)
		}
	}
}

// canonicalSoftKey converts a lowercase header name to the
// canonical form used as a key in softDefaults (Title-Case).
func canonicalSoftKey(lower string) string {
	// softDefaults keys are in http.CanonicalHeaderKey format.
	// We need to match them from the lowercase chromeHeaderOrder.
	for k := range softDefaults {
		if strings.EqualFold(k, lower) {
			return k
		}
	}
	return lower
}

// TestPriorityHeaderInSoftDefaults verifies Chrome 146's Priority
// header is present as a soft default — Chrome sends "u=0, i" on
// every document navigation.
func TestPriorityHeaderInSoftDefaults(t *testing.T) {
	if v, ok := softDefaults["Priority"]; !ok {
		t.Error("Priority missing from softDefaults")
	} else if v != "u=0, i" {
		t.Errorf("Priority = %q, want %q", v, "u=0, i")
	}
}
