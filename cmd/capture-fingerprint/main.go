// capture-fingerprint spawns chromium / Google Chrome as an HTTP
// proxy client, accepts the CONNECT tunnel it opens for the first
// HTTPS navigation, and captures the raw TLS ClientHello bytes the
// browser sends down the tunnel.
//
// The captured bytes are then consumed at runtime by
// internal/proxy/fingerprints via utls.Fingerprinter to build a
// bit-exact `ClientHelloSpec`, which we inject into bogdanfinn/
// tls-client via a custom `ClientHelloID{SpecFactory: ...}`.
//
// This lets fauxbrowser "own" the TLS fingerprint instead of relying
// on bogdanfinn's hand-crafted Chrome_NNN snapshot — which was shown
// to drift by exactly one extension vs real chromium 146 (see
// the tls_fingerprint_ci JA4 test for the drift evidence).
//
// Usage:
//
//	# auto-detect chromium/chrome, write to stdout
//	go run ./cmd/capture-fingerprint
//
//	# pin a specific binary and write to the committed spec file
//	go run ./cmd/capture-fingerprint \
//	    -chrome "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
//	    -out internal/proxy/fingerprints/chrome146.clienthello.hex
//
//	# in CI against nixpkgs chromium
//	nix shell --inputs-from . nixpkgs#chromium --command \
//	    go run ./cmd/capture-fingerprint \
//	    -out internal/proxy/fingerprints/chrome146.clienthello.hex
//
// Why HTTP-proxy-intercept instead of TCP-listener-with-self-signed:
//
//	Initially this tool tried to spawn chromium pointed at
//	`https://127.0.0.1:PORT/` on a plain TCP listener. Chromium
//	on macOS 26 + Chrome 146 simply didn't dial the listener —
//	suspected causes: system proxy PAC file, --headless=new nav
//	quirks, or --dump-dom erroring before the socket opened.
//	Multiple hangs with zero dial attempts observed.
//
//	The HTTP CONNECT proxy approach is bulletproof because Chrome
//	MUST dial the proxy (proxy dials are not subject to system
//	proxy configuration — they ARE the proxy configuration). The
//	CONNECT request arrives reliably, and the bytes after the 200
//	Connection Established response are literally the TLS
//	ClientHello, because Chrome tunnels its HTTPS handshake
//	through the CONNECT session transparently.
//
// How it works:
//
//  1. Listen on 127.0.0.1:0.
//  2. Spawn chromium with `--proxy-server=http://127.0.0.1:PORT` +
//     `--headless=new` pointing at an arbitrary real HTTPS URL
//     (default https://example.com/).
//  3. Chromium opens a TCP connection to our listener and writes
//     `CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n`.
//  4. We read the CONNECT line, reply `HTTP/1.1 200 OK\r\n\r\n`.
//  5. Chromium now treats the connection as a transparent TLS
//     tunnel and writes its ClientHello as the first bytes after
//     the 200 OK.
//  6. We read those bytes, validate the TLS record layer
//     (type 0x16, version 0x03xx, big-endian length), extract the
//     handshake message body, feed to utls.Fingerprinter to
//     round-trip-verify it's parseable, then dump as lowercase hex.
//  7. Close the connection; chromium gives up; we kill the process
//     group (important — chromium spawns helper children that
//     would otherwise outlive the parent and hold our FDs open).
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	utls "github.com/bogdanfinn/utls"
)

func main() {
	chromePath := flag.String("chrome", "", "path to chromium / chrome binary (default: auto-detect)")
	outPath := flag.String("out", "", "output file for hex-encoded ClientHello bytes; empty or '-' = stdout")
	listenAddr := flag.String("listen", "127.0.0.1:0", "local TCP listen address for the HTTP proxy")
	targetURL := flag.String("target", "https://example.com/", "HTTPS URL chromium navigates to through the proxy")
	acceptTimeout := flag.Duration("accept-timeout", 15*time.Second, "how long to wait for chromium's CONNECT")
	hardDeadline := flag.Duration("deadline", 45*time.Second, "hard overall deadline — force-exit if capture hasn't finished in this time")
	verbose := flag.Bool("v", false, "extra logging")
	flag.Parse()

	// Hard backstop: regardless of what's stuck, force-exit after
	// -deadline. Without this a misbehaving chromium can leave the
	// capture tool hanging forever on OS X.
	go func() {
		time.Sleep(*hardDeadline)
		log.Fatalf("capture: hard deadline %s exceeded, aborting", *hardDeadline)
	}()

	u, err := url.Parse(*targetURL)
	if err != nil || u.Host == "" {
		log.Fatalf("parse target URL %q: %v", *targetURL, err)
	}
	wantHost := u.Hostname()

	if *chromePath == "" {
		*chromePath = autodetectChrome()
	}
	if *chromePath == "" {
		log.Fatal("could not find chromium / google-chrome binary; pass -chrome /path/to/binary")
	}
	if *verbose {
		log.Printf("capture: using chromium at %s", *chromePath)
	}

	// TCP listener we'll pretend is an HTTP proxy.
	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer l.Close()
	proxyURL := fmt.Sprintf("http://%s", l.Addr())
	log.Printf("capture: proxy listening on %s", l.Addr())

	// Spawn chromium, configure it to use us as an HTTP proxy, and
	// navigate to the target URL. Chromium must now dial us — there
	// is no fallback path for it to reach the target directly.
	tmpDir, err := os.MkdirTemp("", "capture-chrome-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Note on "background" requests: Chrome pre-dials a bunch of
	// plain-HTTP URLs on startup (clients2.google.com/time for
	// CUP2 time sync, safebrowsing, component updater, etc.) even
	// with --disable-background-networking. These land on our
	// proxy as `GET http://...` requests, NOT `CONNECT host:443`.
	// The main loop skips them (403s them) and keeps accepting
	// until a real CONNECT for our target URL arrives.
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--ignore-certificate-errors",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-dev-shm-usage",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-client-side-phishing-detection",
		"--disable-sync",
		"--disable-extensions",
		"--disable-default-apps",
		"--disable-breakpad",
		"--safebrowsing-disable-auto-update",
		"--metrics-recording-only",
		"--proxy-server=" + proxyURL,
		"--user-data-dir=" + tmpDir,
		"--dump-dom",
		*targetURL,
	}
	cmd := exec.Command(*chromePath, args...)
	// Put chromium in its own process group so we can kill the whole
	// tree (including helper/renderer/GPU subprocesses) on exit.
	// Otherwise macOS leaves helper processes running with our FDs
	// inherited, which keeps the shell pipe open even after our
	// parent process exits.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Never inherit our stdout/stderr: chromium helper processes
	// would keep them open and block any upstream pipe consumer.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		log.Fatalf("spawn chromium: %v", err)
	}
	defer func() {
		// Kill the entire process group, not just the parent.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_, _ = cmd.Process.Wait()
		}
	}()
	log.Printf("capture: spawned chromium pid=%d (pgid=%d)", cmd.Process.Pid, cmd.Process.Pid)

	// Watchdog: if chromium exits early without connecting, close
	// the listener so Accept() returns rather than hanging to
	// deadline.
	cmdExited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(cmdExited)
	}()
	watchdogStop := make(chan struct{})
	defer close(watchdogStop)
	go func() {
		select {
		case <-cmdExited:
			log.Printf("capture: chromium exited early — closing listener")
			_ = l.Close()
		case <-watchdogStop:
		}
	}()

	// Accept connections until we see a CONNECT request. Non-CONNECT
	// requests (Chrome's background time sync / safebrowsing / etc.)
	// get a 403 and we move on.
	deadline := time.Now().Add(*acceptTimeout)
	_ = l.(*net.TCPListener).SetDeadline(deadline)

	var conn net.Conn
	var rdr *bufio.Reader
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatalf("accept: %v (chromium never sent CONNECT — only background HTTP requests)", err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		reqLine, err := br.ReadString('\n')
		if err != nil {
			if *verbose {
				log.Printf("capture: drop %s: %v", c.RemoteAddr(), err)
			}
			_ = c.Close()
			continue
		}
		if *verbose {
			log.Printf("capture: req: %q", strings.TrimSpace(reqLine))
		}
		if !strings.HasPrefix(strings.ToUpper(reqLine), "CONNECT ") {
			// Non-CONNECT = background plain-HTTP request
			// (time sync, component updater, etc.). Reply 403
			// and move on.
			_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			_ = c.Close()
			continue
		}
		// CONNECT — but might be for a background host
		// (safebrowsingohttpgateway.googleapis.com, optimizationguide-pa,
		// accounts.google.com, etc.) Skip those and wait for a
		// CONNECT to our target host.
		//
		// Parse `CONNECT host:port HTTP/1.1` → extract host.
		parts := strings.Fields(reqLine)
		if len(parts) < 2 {
			_ = c.Close()
			continue
		}
		hostPort := parts[1]
		host := hostPort
		if i := strings.LastIndex(hostPort, ":"); i != -1 {
			host = hostPort[:i]
		}
		if host != wantHost {
			if *verbose {
				log.Printf("capture: skip CONNECT to %s (want %s)", host, wantHost)
			}
			// 502 so chromium gives up on this request fast
			// rather than retrying through us — we want it to
			// move on to the target URL navigation.
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			_ = c.Close()
			continue
		}
		// Target CONNECT — this is the one.
		conn = c
		rdr = br
		log.Printf("capture: got target CONNECT from %s: %s", c.RemoteAddr(), strings.TrimSpace(reqLine))
		break
	}
	defer conn.Close()

	// Drain CONNECT request headers up to blank line.
	for {
		line, err := rdr.ReadString('\n')
		if err != nil {
			log.Fatalf("read CONNECT headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// Reply with 200 OK. Chromium will now send TLS bytes.
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Fatalf("write 200 OK: %v", err)
	}
	log.Printf("capture: CONNECT tunnel established, waiting for ClientHello")

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read enough bytes for any ClientHello. 16 KB is generous —
	// typical size is 500–1500 bytes, up to maybe 4 KB with post-
	// quantum X25519MLKEM768 key shares.
	buf := make([]byte, 16*1024)
	n := 0
	if rdr.Buffered() > 0 {
		nb, _ := rdr.Read(buf)
		n = nb
	}
	if n == 0 {
		nb, err := conn.Read(buf)
		if err != nil && nb == 0 {
			log.Fatalf("read ClientHello: %v", err)
		}
		n = nb
	}
	buf = buf[:n]
	if *verbose {
		log.Printf("capture: read %d raw bytes after CONNECT", n)
	}

	record, err := validateTLSRecord(buf)
	if err != nil {
		log.Fatalf("validate TLS record: %v", err)
	}
	log.Printf("capture: TLS record %d bytes (handshake body %d bytes)",
		len(record), len(record)-5)

	// Verify round-trip: parse through utls.Fingerprinter to make sure
	// the captured bytes are a valid ClientHello and utls can rebuild
	// a spec from them. AllowBluntMimicry lets unknown extensions
	// pass through as GenericExtension{Id, Data}, preserving bit-
	// exactness even for extensions utls doesn't have a typed struct
	// for (e.g. application_settings, encrypted_client_hello).
	//
	// NB: bogdanfinn/utls v1.7.7's Fingerprinter wants the FULL TLS
	// Plaintext record (with the 5-byte record layer header), NOT
	// the stripped handshake body. Passing just the body fails with
	// "record is not a handshake".
	f := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := f.FingerprintClientHello(record)
	if err != nil {
		log.Fatalf("fingerprint verification: %v", err)
	}
	log.Printf("capture: verified spec — %d ciphers, %d extensions, TLSVers 0x%04x–0x%04x",
		len(spec.CipherSuites), len(spec.Extensions),
		spec.TLSVersMin, spec.TLSVersMax)

	// Write hex (lowercase, newline-terminated for clean git diffs).
	// We commit the FULL TLS record (with layer header) because
	// that's what utls.Fingerprinter wants at load time.
	hexStr := hex.EncodeToString(record) + "\n"
	if *outPath == "" || *outPath == "-" {
		fmt.Print(hexStr)
		return
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*outPath, []byte(hexStr), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("capture: wrote %s (%d hex chars)", *outPath, len(hexStr)-1)
}

// validateTLSRecord confirms that buf starts with a valid TLS
// Plaintext record containing a ClientHello handshake message, and
// returns the full record (header + body) trimmed to its declared
// length. Returns an error if the record is malformed or truncated.
//
// TLS record layer format (RFC 8446 §5.1):
//
//	struct {
//	    ContentType type;           // 1 byte, 0x16 = handshake
//	    ProtocolVersion legacy_ver; // 2 bytes, 0x0301-0x0304
//	    uint16 length;              // 2 bytes, big-endian
//	    opaque fragment[length];    // the handshake message
//	} TLSPlaintext;
func validateTLSRecord(buf []byte) ([]byte, error) {
	if len(buf) < 5 {
		return nil, errors.New("short read: need 5 bytes for record header")
	}
	if buf[0] != 0x16 {
		return nil, fmt.Errorf("not a handshake record: content_type=0x%02x (want 0x16)", buf[0])
	}
	if buf[1] != 0x03 {
		return nil, fmt.Errorf("not TLS: legacy_record_version=0x%02x%02x", buf[1], buf[2])
	}
	recLen := int(buf[3])<<8 | int(buf[4])
	if 5+recLen > len(buf) {
		return nil, fmt.Errorf("short read: record claims %d bytes but only got %d",
			recLen, len(buf)-5)
	}
	body := buf[5 : 5+recLen]
	if len(body) < 1 || body[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: handshake_type=0x%02x (want 0x01)", body[0])
	}
	return buf[:5+recLen], nil
}

func autodetectChrome() string {
	candidates := []string{
		"chromium",
		"chromium-browser",
		"google-chrome",
		"google-chrome-stable",
		"chrome",
		// macOS app bundles — stat these directly since they're
		// not on PATH.
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	}
	for _, c := range candidates {
		if strings.Contains(c, "/") {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		} else if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}
