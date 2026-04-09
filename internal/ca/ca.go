// Package ca handles CA + leaf certificate generation for fauxbrowser MITM.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Pair bundles a CA cert and its RSA private key.
type Pair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// Generate creates a fresh 2048-bit RSA CA with a random serial, SKI, and
// a 10-year validity window. The CA constrains path length to 0 so it can
// only sign leaf certificates, not other intermediates.
func Generate() (*Pair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fauxbrowser MITM CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Pair{Cert: cert, Key: key}, nil
}

// Load reads a PEM-encoded CA from disk. Supports PKCS#1 and PKCS#8 RSA keys.
func Load(certPath, keyPath string) (*Pair, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("ca cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca key: no PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		return &Pair{Cert: cert, Key: k}, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("ca key: PKCS8 but not RSA")
		}
		return &Pair{Cert: cert, Key: rk}, nil
	}
	return nil, errors.New("ca key: unsupported format")
}

// Write persists the CA to basename.pem + basename.key.
func (p *Pair) Write(basename string) error {
	if err := os.WriteFile(basename+".pem",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Cert.Raw}),
		0o644); err != nil {
		return err
	}
	if err := os.WriteFile(basename+".key",
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(p.Key)}),
		0o600); err != nil {
		return err
	}
	return nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// subjectKeyID computes a stable RFC-5280-style Subject Key Identifier
// (SHA-1 of the DER-encoded SubjectPublicKeyInfo).
func subjectKeyID(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return x509Sha1(der), nil
}

func x509Sha1(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}
