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
