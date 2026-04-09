//go:build tls_fingerprint_ci

// Package proxy — JA3/JA4 cross-client integration test.
//
// Runs ONLY with `-tags tls_fingerprint_ci`. Required build env:
//
//   - chromium on PATH (any nixpkgs chromium works — the test parses
//     its major version and asserts it matches DefaultProfile)
//   - outbound HTTPS to tls.peet.ws (the fingerprint echo service)
//
// Failure modes it catches:
//
//  1. bogdanfinn/tls-client's Chrome_NNN profile drifts from real
//     Chromium NNN — the hand-crafted ClientHello in the library
//     no longer matches what a fresh chromium binary emits. The
//     fast-path ClientHello and the solver-path ClientHello would
//     produce different JA4 fingerprints on the wire, which is the
//     root cause of cross-client cookie portability breaking on
//     JA3-pinning WAFs.
//
//  2. nixpkgs chromium got bumped to a new major and the flake
//     update is ahead of the tls-client bump. The test's first
//     assertion — that both report the same Chrome major — fails
//     loud before the drift reaches production.
//
// The test DOES NOT require WireGuard / the rotator / the fauxbrowser
// Transport. It talks to tls-client and chromedp directly with a
// plain dialer. That's intentional: we're verifying the LIBRARY's
// ClientHello, not the full pipeline.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/chromedp/chromedp"

	chromedpsolver "github.com/onnimonni/fauxbrowser/internal/solver/chromedp"
)

const peetEndpoint = "https://tls.peet.ws/api/all"

// peetResponse is the subset of tls.peet.ws's /api/all JSON we care about.
// Fields we ignore are left out so a schema drift on their side doesn't
// break the test unless it's in one of our load-bearing fields.
type peetResponse struct {
	UserAgent string `json:"user_agent"`
	TLS       struct {
		JA3           string `json:"ja3"`
		JA3Hash       string `json:"ja3_hash"`
		JA4           string `json:"ja4"`
		PeetPrint     string `json:"peetprint"`
		PeetPrintHash string `json:"peetprint_hash"`
	} `json:"tls"`
}

func TestJA4CrossClient(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("chromium fingerprint test is linux-only (nixpkgs chromium not on darwin)")
	}
	if _, err := exec.LookPath("chromium"); err != nil {
		t.Skipf("chromium not on PATH: %v", err)
	}

	// Step 0: verify chromium's major matches DefaultProfile so the
	// rest of the test is meaningful.
	chromiumMajor, err := chromedpsolver.DetectChromiumMajor("")
	if err != nil {
		t.Fatalf("detect chromium major: %v", err)
	}
	defaultProf := SelectProfile(DefaultProfile)
	if chromiumMajor != defaultProf.Major {
		t.Fatalf("chromium major=%d disagrees with DefaultProfile %s (major=%d); "+
			"bump flake.nix chromium or add a chrome%d entry to profileTable",
			chromiumMajor, defaultProf.Name, defaultProf.Major, chromiumMajor)
	}
	t.Logf("chromium major %d matches %s ✓", chromiumMajor, defaultProf.Name)

	// Step 1: fetch tls.peet.ws via bogdanfinn/tls-client with the
	// DefaultProfile TLS fingerprint.
	fastFP, err := fetchPeetViaTLSClient(defaultProf)
	if err != nil {
		t.Fatalf("fetch via tls-client: %v", err)
	}
	t.Logf("tls-client  ja4=%s  ja3_hash=%s  ua=%q",
		fastFP.TLS.JA4, fastFP.TLS.JA3Hash, fastFP.UserAgent)

	// Step 2: fetch tls.peet.ws via chromedp headless chromium, forcing
	// the same UA string that tls-client would send (to model the
	// fauxbrowser solver path, which always forces the profile UA on
	// chromium via --user-agent).
	solverFP, err := fetchPeetViaChromedp(defaultProf.UserAgent)
	if err != nil {
		t.Fatalf("fetch via chromedp: %v", err)
	}
	t.Logf("chromium    ja4=%s  ja3_hash=%s  ua=%q",
		solverFP.TLS.JA4, solverFP.TLS.JA3Hash, solverFP.UserAgent)

	// Both sides should report the same forced Chrome major in the UA.
	// (chromium honors --user-agent; tls-client sets it from the
	// profile bundle.)
	if !strings.Contains(fastFP.UserAgent, fmt.Sprintf("Chrome/%d.", defaultProf.Major)) {
		t.Errorf("tls-client UA does not contain Chrome/%d: %q", defaultProf.Major, fastFP.UserAgent)
	}
	if !strings.Contains(solverFP.UserAgent, fmt.Sprintf("Chrome/%d.", defaultProf.Major)) {
		t.Errorf("chromium UA does not contain Chrome/%d: %q", defaultProf.Major, solverFP.UserAgent)
	}

	// JA4 is the load-bearing comparison because:
	//   - JA3 is order-sensitive; Chrome randomizes extension order
	//     per-handshake since M110 so JA3 hashes may legitimately
	//     differ between two runs of the SAME binary.
	//   - JA4 normalizes extension order (the non-_o variant), so
	//     two Chrome 146 binaries SHOULD produce the same JA4.
	// A JA4 diff here is the actual bug we want to catch: it means
	// bogdanfinn/tls-client's Chrome_NNN snapshot has drifted from
	// what real chromium NNN sends on the wire, and solver cookies
	// will not port to the fast path on JA4-pinning WAFs.
	if fastFP.TLS.JA4 != solverFP.TLS.JA4 {
		t.Errorf("JA4 mismatch — bogdanfinn Chrome_%d snapshot has drifted from real chromium %d:\n  tls-client: %s\n  chromium:   %s",
			defaultProf.Major, chromiumMajor, fastFP.TLS.JA4, solverFP.TLS.JA4)
	}
}

func fetchPeetViaTLSClient(p BrowserProfile) (*peetResponse, error) {
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
		tls_client.WithTimeoutSeconds(20),
		tls_client.WithClientProfile(p.TLSProfile),
		tls_client.WithRandomTLSExtensionOrder(),
	)
	if err != nil {
		return nil, fmt.Errorf("new tls-client: %w", err)
	}
	req, err := fhttp.NewRequest(fhttp.MethodGet, peetEndpoint, nil)
	if err != nil {
		return nil, err
	}
	// Mirror applyProfileDefaults — the forced headers that fauxbrowser
	// stamps on every outbound request.
	req.Header.Del("User-Agent")
	req.Header.Add("User-Agent", p.UserAgent)
	req.Header.Del("sec-ch-ua")
	req.Header.Add("sec-ch-ua", p.SecChUa)
	req.Header.Add("sec-ch-ua-mobile", p.SecChUaMob)
	req.Header.Add("sec-ch-ua-platform", p.Platform)
	req.Header.Add("Accept", "*/*")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("tls.peet.ws status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out peetResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("unmarshal: %w (body=%q)", err, string(body))
	}
	return &out, nil
}

func fetchPeetViaChromedp(userAgent string) (*peetResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	flags := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-gpu", true),
		chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.UserAgent(userAgent),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, flags...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	// Chromium's default behavior on a /api/all JSON URL is to render
	// the JSON inside a <pre> element. Grab that text.
	var body string
	err := chromedp.Run(browserCtx,
		chromedp.Navigate(peetEndpoint),
		chromedp.WaitVisible("pre", chromedp.ByQuery),
		chromedp.Text("pre", &body, chromedp.ByQuery),
	)
	if err != nil {
		return nil, fmt.Errorf("chromedp run: %w", err)
	}
	// Fallback: some chromium builds render the JSON directly in the
	// document body without wrapping it in a <pre>. If `pre` extraction
	// yielded nothing, try grabbing the whole body.
	if strings.TrimSpace(body) == "" {
		if err := chromedp.Run(browserCtx,
			chromedp.Text("body", &body, chromedp.ByQuery),
		); err != nil {
			return nil, fmt.Errorf("chromedp body fallback: %w", err)
		}
	}
	var out peetResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return nil, fmt.Errorf("unmarshal: %w (body=%q)", err, body)
	}
	return &out, nil
}

