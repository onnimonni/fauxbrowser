# fauxbrowser development notes

## Updating when Chrome bumps to a new major version

When nixpkgs ships a new Chrome major (e.g. 146 → 147), four fingerprint
layers need updating. CI's `tls-fingerprint` job will fail on drift.

### 1. Capture new TLS ClientHello

```bash
go run ./cmd/capture-fingerprint \
  -out internal/proxy/fingerprints/chrome146.clienthello.hex
```

Rename the hex file to match the new version. Auto-detects Chrome on
PATH or macOS app bundle. Uses HTTP CONNECT proxy approach — spawns
Chrome with `--proxy-server` pointed at a local TCP listener, skips
background CONNECTs (safebrowsing, accounts.google.com, etc.), captures
the first CONNECT to the target URL.

### 2. Add new profile entry

In `internal/proxy/profiles.go`:

1. Add a new `chromeNNN` entry to `profileTable` with matching Major,
   UserAgent, SecChUa values.
2. Build a new `chromeNNNCaptured` custom `profiles.ClientProfile` via
   `profiles.NewClientProfile()` with the new `SpecFactory` pointing
   at the new hex file. Inherit h2 settings from the closest
   bogdanfinn Chrome profile (`profiles.Chrome_NNN` if it exists,
   otherwise reuse the previous one's h2 config).
3. Update `DefaultProfile` and `LatestAlias` constants.

### 3. Verify h2 header order

Run fauxbrowser and hit `tls.peet.ws/api/all` through the fast path:

```bash
curl -sS -H "X-Target-URL: https://tls.peet.ws/api/all" http://127.0.0.1:18543/ | python3 -c "
import sys, json
d = json.load(sys.stdin)
for f in d['http2']['sent_frames']:
  if f['frame_type'] == 'HEADERS':
    for h in f['headers']:
      print(h)
"
```

Compare with Chrome's output (navigate same URL in Chrome, or use
Playwright). If the regular header order changed, update
`chromeHeaderOrder` in `profiles.go`.

The Akamai h2 fingerprint (SETTINGS + WINDOW_UPDATE + pseudo-header
order + PRIORITY) rarely changes between Chrome majors. Verify the
`akamai_fingerprint` field matches. If it drifted, update the h2
settings in `profiles.NewClientProfile()`.

### 4. Update tests

- `profiles_test.go#TestChromeHeaderOrderMatchesCapture` — update the
  `want` slice if header order changed.
- `profiles_test.go#TestProfileCoherence` — runs automatically if the
  new profile entry follows the `chromeNNN` naming convention.
- CI's `tls_fingerprint_ci` tag — `ja3_integration_test.go` compares
  tls-client JA4 against real chromium. Will auto-pass if the new
  captured hex is correct.

### 5. Push and verify CI

```bash
git push origin HEAD
gh run watch <run-id> --exit-status
```

Both `test` and `tls-fingerprint` jobs must pass.

## Key files

| File | Purpose |
|------|---------|
| `cmd/capture-fingerprint/main.go` | Capture Chrome's TLS ClientHello via HTTP CONNECT proxy |
| `internal/proxy/fingerprints/chrome146.clienthello.hex` | Committed hex of captured ClientHello |
| `internal/proxy/fingerprints/fingerprints.go` | Loads hex → `utls.ClientHelloSpec` via `Fingerprinter` |
| `internal/proxy/profiles.go` | Profile table + `chromeHeaderOrder` + soft defaults |
| `internal/proxy/profiles_test.go` | Coherence + header order tests |
| `internal/proxy/ja3_integration_test.go` | CI JA4 drift test (`//go:build tls_fingerprint_ci`) |
| `internal/proxy/reconcile.go` | Chromium version ↔ profile reconciliation |
| `internal/solver/chromedp/version.go` | `DetectChromiumMajor()` from binary |
| `internal/solver/cache.go` | Solver cookie cache + per-host circuit breaker |

## Fingerprint layers (all must agree)

1. **TLS ClientHello** (JA4) — captured from real Chrome binary via
   `cmd/capture-fingerprint`. Injected into tls-client via
   `ClientHelloID{SpecFactory}`.
2. **h2 SETTINGS + WINDOW_UPDATE** — inherited from bogdanfinn's
   `profiles.Chrome_NNN` via `GetSettings()` etc. Verified via
   `tls.peet.ws` Akamai h2 fingerprint hash.
3. **h2 header order** — `chromeHeaderOrder` in `profiles.go`. Verified
   via `tls.peet.ws` HEADERS frame dump.
4. **HTTP headers** — forced: UA + sec-ch-ua bundle. Soft defaults:
   Accept, Accept-Language, Accept-Encoding, Sec-Fetch-*, Priority.

## Testing k-ruoka.fi (or similar CF Enterprise targets)

```bash
# Start locally with WG conf
./fauxbrowser -wg-conf /path/to/proton.conf -vpn-country NL \
  -solver chromedp -chromium-path "$(which chromium)"

# Test via fast path
curl -H "X-Target-URL: https://www.k-ruoka.fi/" \
     -H "Accept-Language: fi-FI,fi;q=0.9,en;q=0.8" \
     http://127.0.0.1:18443/
```

Expected: HTTP 200 on fast path without solver invocation (as of
2026-04-09 with Chrome 146 profile). If it 403s, check:
- VPN exit IP reputation (try `curl -H "X-Target-URL: https://example.com/" ...` first)
- Header order drift (compare `tls.peet.ws` output)
- TLS JA4 drift (run `tls_fingerprint_ci` tests)
