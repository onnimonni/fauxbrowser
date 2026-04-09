package proxy

import (
	"fmt"
	"log/slog"
)

// ReconcileProfile picks the BrowserProfile name fauxbrowser should use
// given a user-requested profile name and the Chrome major version of
// the Chromium binary the chromedp solver is going to launch.
//
// Rules:
//
//  1. chromiumMajor == 0 means "solver disabled / not detected" — we
//     just fall through to SelectProfile(requested) and return its
//     name. No version check is possible.
//
//  2. requested empty or "latest" + chromiumMajor known:
//     → pick the profile table entry with matching Major. If one
//       exists, return it. If none (chromium is newer than every
//       profile bogdanfinn/tls-client ships), the behavior depends
//       on allowMismatch:
//         false → error. The operator must bump tls-client, downgrade
//                 chromium, or pass -allow-version-mismatch.
//         true  → loud warn + return DefaultProfile. Solve-time and
//                 fast-path TLS fingerprints will differ by at least
//                 one major version; cookie portability is at risk.
//
//  3. requested explicit + chromiumMajor known:
//     → resolve to a table entry via SelectProfile. If its Major
//       equals chromiumMajor, return it. Otherwise behavior depends
//       on allowMismatch:
//         false → error.
//         true  → loud warn + return the explicitly requested name.
//
// The function is deliberately a pure mapper (it logs but does no I/O)
// so profiles_test can exercise it without touching real Chromium.
func ReconcileProfile(requested string, chromiumMajor int, allowMismatch bool) (string, error) {
	// Solver disabled / version unknown: classic fallback path.
	if chromiumMajor == 0 {
		return SelectProfile(requested).Name, nil
	}

	// Auto-select mode: empty or "latest" and we know chromium major.
	isAuto := requested == "" || requested == LatestAlias || requested == "LATEST"
	if isAuto {
		if p, ok := SelectProfileForMajor(chromiumMajor); ok {
			slog.Info("profile: auto-selected from chromium version",
				"chromium_major", chromiumMajor, "profile", p.Name)
			return p.Name, nil
		}
		if !allowMismatch {
			return "", fmt.Errorf("chromium major %d has no matching profile in tls-client table (known: %v); "+
				"bump bogdanfinn/tls-client and add a chrome%d entry, pin an older chromium, "+
				"or pass -allow-version-mismatch to run with profile=%s (solve/fast-path JA3 will differ)",
				chromiumMajor, KnownProfiles(), chromiumMajor, DefaultProfile)
		}
		slog.Warn("profile: chromium newer than any tls-client profile — mismatch allowed by operator",
			"chromium_major", chromiumMajor,
			"fallback", DefaultProfile,
			"warning", "solver's chromium ClientHello and fast-path Chrome_"+DefaultProfile[6:]+" ClientHello WILL differ; cookie portability may break on JA3-pinning WAFs")
		return DefaultProfile, nil
	}

	// Explicit profile: require exact agreement.
	sel := SelectProfile(requested)
	if sel.Major == chromiumMajor {
		return sel.Name, nil
	}
	if !allowMismatch {
		return "", fmt.Errorf("profile=%s (Chrome %d) does not match chromium major %d; "+
			"use -profile=latest to auto-pick, upgrade/downgrade chromium, "+
			"or pass -allow-version-mismatch to keep the explicit profile",
			sel.Name, sel.Major, chromiumMajor)
	}
	slog.Warn("profile: explicit profile disagrees with chromium — mismatch allowed by operator",
		"profile", sel.Name,
		"profile_major", sel.Major,
		"chromium_major", chromiumMajor,
		"warning", "solver's chromium ClientHello and fast-path ClientHello WILL differ; cookie portability may break on JA3-pinning WAFs")
	return sel.Name, nil
}
