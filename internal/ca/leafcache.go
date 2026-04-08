package ca

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// LeafCache is a bounded LRU of MITM leaf certificates keyed by SNI host.
// Concurrent misses for the same host coalesce via singleflight so we
// never double-sign. Misses for different hosts run in parallel.
type LeafCache struct {
	signer *Pair
	max    int

	mu sync.Mutex
	ll *list.List
	m  map[string]*list.Element

	sf singleflight.Group
}

type leafEntry struct {
	key  string
	cert *tls.Certificate
}

func NewLeafCache(signer *Pair, max int) *LeafCache {
	if max <= 0 {
		max = 1024
	}
	return &LeafCache{
		signer: signer,
		max:    max,
		ll:     list.New(),
		m:      make(map[string]*list.Element, max),
	}
}

// Get returns a leaf cert for host, minting one on first access.
func (c *LeafCache) Get(host string) (*tls.Certificate, error) {
	if cert := c.lookup(host); cert != nil {
		return cert, nil
	}
	v, err, _ := c.sf.Do(host, func() (any, error) {
		// Double-check under singleflight: another goroutine may have
		// populated the cache between our first lookup and the Do call.
		if cert := c.lookup(host); cert != nil {
			return cert, nil
		}
		cert, err := c.mint(host)
		if err != nil {
			return nil, err
		}
		c.put(host, cert)
		return cert, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

func (c *LeafCache) lookup(host string) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[host]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*leafEntry).cert
	}
	return nil
}

func (c *LeafCache) put(host string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[host]; ok {
		el.Value.(*leafEntry).cert = cert
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&leafEntry{key: host, cert: cert})
	c.m[host] = el
	for c.ll.Len() > c.max {
		back := c.ll.Back()
		if back == nil {
			break
		}
		delete(c.m, back.Value.(*leafEntry).key)
		c.ll.Remove(back)
	}
}

func (c *LeafCache) mint(host string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	ski, _ := subjectKeyIDECDSA(&leafKey.PublicKey)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		// < 398 days keeps us inside CA/B baseline for clients that care.
		NotAfter:              time.Now().Add(397 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        c.signer.Cert.SubjectKeyId,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.signer.Cert, &leafKey.PublicKey, c.signer.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.signer.Cert.Raw},
		PrivateKey:  leafKey,
	}, nil
}

func subjectKeyIDECDSA(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return x509Sha1(der), nil
}
