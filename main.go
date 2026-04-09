// fauxbrowser - a tiny HTTP proxy that fakes browser TLS fingerprints.
//
// Two ways to use it:
//
//  1. CONNECT / MITM mode: `curl -x http://127.0.0.1:18443 --cacert ca.pem https://...`
//     The proxy terminates the curl-side TLS with a leaf cert signed by its
//     own CA and re-fetches the URL via bogdanfinn/tls-client so the REAL
//     TLS handshake to the target uses a browser fingerprint.
//
//  2. Header mode (no CA needed): `curl http://127.0.0.1:18443 -H 'X-Target-URL: https://...'`
//     curl talks plain HTTP to fauxbrowser, fauxbrowser fetches the URL from the
//     header via tls-client, returns the body. No MITM, no CA, no cert trust.
//
// Optional upstream proxy (e.g. gluetun WireGuard HTTP proxy) chains the
// tls-client fetch through a VPN egress.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

var (
	listenAddr  = flag.String("listen", "127.0.0.1:18443", "address to listen on")
	upstreamURL = flag.String("upstream", "", "upstream HTTP proxy URL (e.g. http://127.0.0.1:18888 for gluetun). Empty = direct")
	profileName = flag.String("profile", "chrome146", "tls-client browser profile: chrome146|chrome144|chrome133|chrome120|firefox123|safari16")
	caCertFlag  = flag.String("ca-cert", "", "path to existing CA cert PEM (used for MITM mode). Auto-generated if missing")
	caKeyFlag   = flag.String("ca-key", "", "path to existing CA private key PEM (used for MITM mode). Auto-generated if missing")
	caOutFlag   = flag.String("ca-out", "", "if set and CA was auto-generated, write cert+key to this basename (.pem and .key)")
	headerName  = flag.String("target-header", "X-Target-URL", "header name whose value is the upstream URL in header mode")
	timeoutSecs = flag.Int("timeout", 60, "per-request upstream timeout (seconds)")
)

// --- browser profile table ---

func selectProfile(name string) profiles.ClientProfile {
	switch strings.ToLower(name) {
	case "chrome146", "chrome", "latest":
		return profiles.Chrome_146
	case "chrome144":
		return profiles.Chrome_144
	case "chrome133":
		return profiles.Chrome_133
	case "chrome120":
		return profiles.Chrome_120
	case "firefox123":
		return profiles.Firefox_123
	case "safari16":
		return profiles.Safari_16_0
	default:
		log.Printf("unknown profile %q, falling back to chrome146", name)
		return profiles.Chrome_146
	}
}

// --- CA + leaf-cert machinery ---

type leafCache struct {
	mu     sync.Mutex
	m      map[string]*tls.Certificate
	signer *x509.Certificate
	key    *rsa.PrivateKey
}

func (c *leafCache) get(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.m[host]; ok {
		return cert, nil
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.signer, &leafKey.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, c.signer.Raw},
		PrivateKey:  leafKey,
	}
	c.m[host] = cert
	return cert, nil
}

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fauxbrowser MITM CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, errors.New("ca cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("ca key: no PEM block")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		key = k
	} else if k2, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		rk, ok := k2.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("ca key: not RSA")
		}
		key = rk
	} else {
		return nil, nil, errors.New("ca key: unsupported format")
	}
	return cert, key, nil
}

func writeCA(cert *x509.Certificate, key *rsa.PrivateKey, basename string) error {
	certFile := basename + ".pem"
	keyFile := basename + ".key"
	if err := os.WriteFile(certFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		0o600); err != nil {
		return err
	}
	log.Printf("CA cert: %s  key: %s", certFile, keyFile)
	return nil
}

// --- tls-client factory ---

func newTLSClient() (tls_client.HttpClient, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(*timeoutSecs),
		tls_client.WithClientProfile(selectProfile(*profileName)),
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithRandomTLSExtensionOrder(),
	}
	if *upstreamURL != "" {
		opts = append(opts, tls_client.WithProxyUrl(*upstreamURL))
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

// --- the shared "fetch via tls-client" helper ---

func fetchUpstream(client tls_client.HttpClient, method, rawURL string, headers http.Header, body io.Reader) (int, http.Header, []byte, error) {
	bodyBytes, _ := io.ReadAll(body)
	freq, err := fhttp.NewRequest(method, rawURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vs := range headers {
		lk := strings.ToLower(k)
		if lk == "proxy-connection" || lk == "connection" || lk == "keep-alive" ||
			lk == "host" || lk == strings.ToLower(*headerName) {
			continue
		}
		for _, v := range vs {
			freq.Header.Add(k, v)
		}
	}
	fresp, err := client.Do(freq)
	if err != nil {
		return 0, nil, nil, err
	}
	defer fresp.Body.Close()
	respBody, err := io.ReadAll(fresp.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	h := http.Header{}
	for k, vs := range fresp.Header {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	return fresp.StatusCode, h, respBody, nil
}

// isSelfHost reports whether h refers to the proxy's own listener.
// Accepts "host", "host:port", "ip", "ip:port", and common loopback aliases.
func isSelfHost(h, listenHost, listenAddr string) bool {
	if h == listenAddr {
		return true
	}
	hh, _, err := net.SplitHostPort(h)
	if err != nil {
		hh = h
	}
	if hh == "" {
		return true
	}
	if hh == listenHost {
		return true
	}
	// Listening on :: / 0.0.0.0 — any loopback or local IP is "us".
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" {
		if hh == "localhost" || hh == "127.0.0.1" || hh == "::1" {
			return true
		}
		if ip := net.ParseIP(hh); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

// --- handlers ---

func main() {
	flag.Parse()

	// CA bootstrap
	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey
	if *caCertFlag != "" && *caKeyFlag != "" {
		c, k, err := loadCA(*caCertFlag, *caKeyFlag)
		if err != nil {
			log.Fatalf("load CA: %v", err)
		}
		caCert, caKey = c, k
		log.Printf("loaded CA from %s + %s", *caCertFlag, *caKeyFlag)
	} else {
		c, k, err := generateCA()
		if err != nil {
			log.Fatalf("generate CA: %v", err)
		}
		caCert, caKey = c, k
		log.Printf("generated ephemeral CA (install cert in trust store to silence curl errors)")
		if *caOutFlag != "" {
			if err := writeCA(caCert, caKey, *caOutFlag); err != nil {
				log.Fatalf("write CA: %v", err)
			}
		}
	}
	cache := &leafCache{m: map[string]*tls.Certificate{}, signer: caCert, key: caKey}

	client, err := newTLSClient()
	if err != nil {
		log.Fatalf("new tls-client: %v", err)
	}
	upstreamDesc := *upstreamURL
	if upstreamDesc == "" {
		upstreamDesc = "(direct)"
	}
	listenHost, _, _ := net.SplitHostPort(*listenAddr)
	log.Printf("fauxbrowser — profile=%s upstream=%s listen=%s", *profileName, upstreamDesc, *listenAddr)

	srv := &http.Server{
		Addr: *listenAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r, cache, client)
				return
			}
			if t := r.Header.Get(*headerName); t != "" {
				handleHeaderMode(w, r, client, t)
				return
			}
			if r.URL.IsAbs() {
				// Classic forward-proxy: absolute URI in request line.
				handleHeaderMode(w, r, client, r.URL.String())
				return
			}
			// Host-header mode: the client's Host header names the target.
			// Triggers when r.Host is not us (the proxy's own listen host).
			if r.Host != "" && !isSelfHost(r.Host, listenHost, *listenAddr) {
				scheme := r.Header.Get("X-Target-Scheme")
				if scheme == "" {
					scheme = "https"
				}
				target := scheme + "://" + r.Host + r.URL.RequestURI()
				handleHeaderMode(w, r, client, target)
				return
			}
			http.Error(w, "fauxbrowser: send CONNECT, set "+*headerName+", send an absolute-URI request, or set a Host header naming the target", http.StatusBadRequest)
		}),
	}
	log.Fatal(srv.ListenAndServe())
}

func handleHeaderMode(w http.ResponseWriter, r *http.Request, client tls_client.HttpClient, target string) {
	if _, err := url.Parse(target); err != nil {
		http.Error(w, "bad target url: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("HDR → %s %s", r.Method, target)
	code, hdr, body, err := fetchUpstream(client, r.Method, target, r.Header, r.Body)
	if err != nil {
		log.Printf("HDR upstream: %v", err)
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("HDR ← %d %s (%d bytes)", code, target, len(body))
	for k, vs := range hdr {
		lk := strings.ToLower(k)
		if lk == "transfer-encoding" || lk == "content-length" || lk == "content-encoding" || lk == "connection" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(code)
	w.Write(body)
}

func handleConnect(w http.ResponseWriter, r *http.Request, cache *leafCache, client tls_client.HttpClient) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijacker", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			h := host
			if hello.ServerName != "" {
				h = hello.ServerName
			}
			return cache.get(h)
		},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("MITM tls handshake: %v", err)
		return
	}
	defer tlsConn.Close()

	br := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		if err != io.EOF {
			log.Printf("read req: %v", err)
		}
		return
	}
	target := &url.URL{Scheme: "https", Host: r.Host, Path: req.URL.Path, RawQuery: req.URL.RawQuery}
	log.Printf("MITM → %s %s", req.Method, target)

	code, hdr, body, err := fetchUpstream(client, req.Method, target.String(), req.Header, req.Body)
	req.Body.Close()
	if err != nil {
		log.Printf("MITM upstream: %v", err)
		fmt.Fprintf(tlsConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(err.Error()), err.Error())
		return
	}
	log.Printf("MITM ← %d %s (%d bytes)", code, target, len(body))
	fmt.Fprintf(tlsConn, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	for k, vs := range hdr {
		lk := strings.ToLower(k)
		if lk == "transfer-encoding" || lk == "content-length" || lk == "content-encoding" || lk == "connection" {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(tlsConn, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(tlsConn, "Content-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	tlsConn.Write(body)
}
