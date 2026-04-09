package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGenerateAndLoadRoundtrip(t *testing.T) {
	pair, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !pair.Cert.IsCA {
		t.Fatal("not a CA")
	}
	if pair.Cert.MaxPathLen != 0 || !pair.Cert.MaxPathLenZero {
		t.Errorf("CA path-length cap not set")
	}
	if len(pair.Cert.SubjectKeyId) == 0 {
		t.Errorf("missing SKI")
	}

	dir := t.TempDir()
	base := filepath.Join(dir, "test-ca")
	if err := pair.Write(base); err != nil {
		t.Fatalf("write: %v", err)
	}
	loaded, err := Load(base+".pem", base+".key")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.Cert.Equal(pair.Cert) {
		t.Errorf("loaded cert != generated")
	}
	if loaded.Key.N.Cmp(pair.Key.N) != 0 {
		t.Errorf("loaded key != generated")
	}
	// Ensure key file has tight perms.
	info, _ := os.Stat(base + ".key")
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key perms: got %v want 0600", info.Mode().Perm())
	}
}

func TestLeafCacheChainsToCA(t *testing.T) {
	pair, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cache := NewLeafCache(pair, 16)
	cert, err := cache.Get("example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(pair.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "example.com",
	}); err != nil {
		t.Errorf("chain verify failed: %v", err)
	}
}

func TestLeafCacheSingleflightAndLRU(t *testing.T) {
	pair, _ := Generate()
	cache := NewLeafCache(pair, 3)

	// Concurrent misses for same host → one mint.
	var wg sync.WaitGroup
	var certs [10]*x509.Certificate
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := cache.Get("race.example")
			if err != nil {
				t.Errorf("get: %v", err)
				return
			}
			certs[i], _ = x509.ParseCertificate(c.Certificate[0])
		}(i)
	}
	wg.Wait()
	for i := 1; i < 10; i++ {
		if !certs[i].Equal(certs[0]) {
			t.Fatalf("singleflight failed: cert %d differs", i)
		}
	}

	// LRU eviction: max=3, insert 5 hosts, first two should be gone.
	hosts := []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
	for _, h := range hosts {
		if _, err := cache.Get(h); err != nil {
			t.Fatal(err)
		}
	}
	if cache.lookup("a.example") != nil {
		t.Errorf("a.example should be evicted")
	}
	if cache.lookup("b.example") != nil {
		t.Errorf("b.example should be evicted")
	}
	if cache.lookup("e.example") == nil {
		t.Errorf("e.example should still be cached")
	}
}
