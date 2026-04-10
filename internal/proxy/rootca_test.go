package proxy

import (
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// Regression test for issue #7. On NixOS/systemd the CA bundle is
// commonly provided via NIX_SSL_CERT_FILE; fauxbrowser must load it
// explicitly into tls-client's root pool so upstream HTTPS can verify.
func TestTransportLoadsRootCAsFromNIXSSLCertFile(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	bundlePath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: upstream.Certificate().Raw,
	})
	if err := os.WriteFile(bundlePath, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}

	t.Setenv("NIX_SSL_CERT_FILE", bundlePath)
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	dialer := fakeContextDialer{
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != targetURL.Host {
				t.Fatalf("dialed %q, want %q", address, targetURL.Host)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, targetURL.Host)
		},
	}

	tr, err := NewTransport(TransportOptions{
		Dialer:         dialer,
		TimeoutSeconds: 5,
		Profile:        "chrome146",
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	defer tr.Close()

	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}
