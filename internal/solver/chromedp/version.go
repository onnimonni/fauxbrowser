package chromedp

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// versionRe matches the first `N.N.N.N` quadruple in a `chromium
// --version` / `google-chrome --version` output. Captures the major.
//
// Example outputs we handle:
//   "Chromium 146.0.7680.177"
//   "Chromium 146.0.7680.177 snap"
//   "Google Chrome 146.0.7190.80 "
//   "Chromium 146.0.7680.177 Built on Ubuntu..."
var versionRe = regexp.MustCompile(`\b(\d+)\.\d+\.\d+\.\d+\b`)

// DetectChromiumMajor runs `{binary} --version` and parses the Chrome
// major version number from stdout.
//
// If path is empty, the same name list as ChromiumAvailable is tried
// (chromium, chrome, google-chrome, google-chrome-stable,
// chromium-browser), and the first one on PATH is used. Returns a
// non-nil error if no binary is found or the version string cannot
// be parsed.
//
// Used by fauxbrowser's startup guard to verify that the Chromium the
// chromedp solver will launch has the same Chrome major version as
// the active bogdanfinn/tls-client profile — a mismatch means the
// solve-time TLS fingerprint differs from the fast-path fingerprint
// even on "same major", which breaks cookie portability for WAFs
// that JA3-pin cf_clearance.
func DetectChromiumMajor(path string) (int, error) {
	bin := path
	if bin == "" {
		for _, name := range []string{"chromium", "chrome", "google-chrome", "google-chrome-stable", "chromium-browser"} {
			if _, err := exec.LookPath(name); err == nil {
				bin = name
				break
			}
		}
	}
	if bin == "" {
		return 0, fmt.Errorf("no chromium binary found on PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return 0, fmt.Errorf("exec %s --version: %w", bin, err)
	}
	m := versionRe.FindStringSubmatch(string(out))
	if m == nil {
		return 0, fmt.Errorf("parse version from %q: no N.N.N.N quadruple", string(out))
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("parse major %q: %w", m[1], err)
	}
	return major, nil
}
