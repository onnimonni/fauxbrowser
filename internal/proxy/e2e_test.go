package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	nurl "net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onnimonni/fauxbrowser/internal/ca"
	"github.com/onnimonni/fauxbrowser/internal/proxy"
)

// newTestEnv spins up a dummy HTTPS origin and a fauxbrowser server pointing
// at it. Returns a function to clean up.
func newTestEnv(t *testing.T) (originURL string, proxyURL string, caPEM []byte, cleanup func()) {
	t.Helper()

	var mu sync.Mutex
	var lastSeen http.Header

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastSeen = r.Header.Clone()
		mu.Unlock()
		switch r.URL.Path {
		case "/slow":
			select {
			case <-time.After(10 * time.Second):
				w.WriteHeader(200)
			case <-r.Context().Done():
				return
			}
		case "/big":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(200)
			buf := make([]byte, 64*1024)
			for i := 0; i < 64; i++ {
				_, _ = w.Write(buf)
			}
		default:
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "ok:%s ua:%s", r.URL.Path, r.Header.Get("User-Agent"))
		}
	}))

	_ = lastSeen

	pair, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca gen: %v", err)
	}
	leafCache := ca.NewLeafCache(pair, 16)

	transport := proxy.NewTransport(proxy.TransportOptions{
		DefaultProfile: "chrome146",
		TimeoutSeconds: 15,
		Insecure:       true, // accept httptest's self-signed origin cert
		ProfileHeader:  "X-Fauxbrowser-Profile",
		SessionHeader:  "X-Fauxbrowser-Session",
		MaxSessions:    8,
	})
	mitm := proxy.NewMITM(leafCache, transport)

	h := proxy.NewHandler(proxy.Options{
		ListenAddr:   "127.0.0.1:0",
		TargetHeader: "X-Target-URL",
		Transport:    transport,
		MITM:         mitm,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)

	// PEM-encode the CA cert for curl-like client usage.
	caPEM = pemEncodeCert(pair.Cert.Raw)

	cleanup = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = mitm.Shutdown(ctx)
		transport.Close()
		origin.Close()
	}
	return origin.URL, "http://" + ln.Addr().String(), caPEM, cleanup
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A client that speaks to our fauxbrowser via plain HTTP.
func httpClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

// A client that uses our fauxbrowser as a CONNECT proxy and trusts the
// provided CA as the root for its decrypted side.
func mitmClient(proxyURL string, caPEM []byte) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	u, _ := nurl.Parse(proxyURL)
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: true},
		},
	}
}

func TestHeaderMode(t *testing.T) {
	origin, proxyURL, _, cleanup := newTestEnv(t)
	defer cleanup()

	req, _ := http.NewRequest("GET", proxyURL+"/", nil)
	req.Header.Set("X-Target-URL", origin+"/hello")
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "ok:/hello") {
		t.Errorf("body: %q", body)
	}
}

func TestHostHeaderMode(t *testing.T) {
	origin, proxyURL, _, cleanup := newTestEnv(t)
	defer cleanup()
	u, _ := nurl.Parse(origin)

	req, _ := http.NewRequest("GET", proxyURL+"/hostmode", nil)
	req.Host = u.Host
	req.Header.Set("X-Target-Scheme", "https")
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "ok:/hostmode") {
		t.Errorf("body: %q", body)
	}
}

func TestMITMMode(t *testing.T) {
	origin, proxyURL, caPEM, cleanup := newTestEnv(t)
	defer cleanup()

	client := mitmClient(proxyURL, caPEM)
	resp, err := client.Get(origin + "/mitm")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "ok:/mitm") {
		t.Errorf("body: %q", body)
	}
}

func TestStreamingLargeBody(t *testing.T) {
	origin, proxyURL, caPEM, cleanup := newTestEnv(t)
	defer cleanup()
	client := mitmClient(proxyURL, caPEM)
	resp, err := client.Get(origin + "/big")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if n != 64*64*1024 {
		t.Errorf("got %d bytes, want %d", n, 64*64*1024)
	}
}

func TestContextCancellation(t *testing.T) {
	origin, proxyURL, _, cleanup := newTestEnv(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", proxyURL+"/", nil)
	req.Header.Set("X-Target-URL", origin+"/slow")
	start := time.Now()
	_, err := httpClient().Do(req)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error from cancellation")
	}
	if elapsed > 3*time.Second {
		t.Errorf("cancellation took too long: %v", elapsed)
	}
}

func TestAllowList(t *testing.T) {
	origin, _, caPEM, cleanup := newTestEnv(t)
	defer cleanup()
	_ = caPEM

	// Wrap a fresh handler with an allow-list that excludes httptest origin.
	pair, _ := ca.Generate()
	leafCache := ca.NewLeafCache(pair, 16)
	tr := proxy.NewTransport(proxy.TransportOptions{
		DefaultProfile: "chrome146", TimeoutSeconds: 5, Insecure: true,
	})
	defer tr.Close()
	mitm := proxy.NewMITM(leafCache, tr)
	defer mitm.Shutdown(context.Background())

	h := proxy.NewHandler(proxy.Options{
		ListenAddr: "127.0.0.1:0", TargetHeader: "X-Target-URL", Transport: tr, MITM: mitm,
	})
	h = proxy.HostAllowList(h, []string{"allowed.example.com"}, "X-Target-URL")

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
	req.Header.Set("X-Target-URL", origin+"/denied")
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: %d want 403", resp.StatusCode)
	}
}

func TestBasicAuth(t *testing.T) {
	origin, _, _, cleanup := newTestEnv(t)
	defer cleanup()

	pair, _ := ca.Generate()
	leafCache := ca.NewLeafCache(pair, 16)
	tr := proxy.NewTransport(proxy.TransportOptions{
		DefaultProfile: "chrome146", TimeoutSeconds: 5, Insecure: true,
	})
	defer tr.Close()
	mitm := proxy.NewMITM(leafCache, tr)
	defer mitm.Shutdown(context.Background())

	h := proxy.NewHandler(proxy.Options{
		ListenAddr: "127.0.0.1:0", TargetHeader: "X-Target-URL", Transport: tr, MITM: mitm,
	})
	h = proxy.BasicAuth(h, "user:pass")

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
	req.Header.Set("X-Target-URL", origin+"/")
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("no-auth status: %d want 407", resp.StatusCode)
	}

	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	resp2, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Errorf("with-auth status: %d want 200", resp2.StatusCode)
	}
}
