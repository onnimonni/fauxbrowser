// Package fingerprints owns the TLS ClientHelloSpecs fauxbrowser
// forges on the wire. It replaces bogdanfinn/tls-client's hand-
// crafted Chrome_NNN snapshots with specs captured directly from
// the chromium binary we ship with.
//
// Source of truth:
//
//	internal/proxy/fingerprints/chrome146.clienthello.hex
//
// That file is a hex-encoded TLS Plaintext record (content type 0x16,
// legacy_record_version 0x0301, 16-bit length, handshake body) that
// was captured from a real chromium 146 binary via:
//
//	go run ./cmd/capture-fingerprint \
//	    -out internal/proxy/fingerprints/chrome146.clienthello.hex
//
// At package init time the hex is decoded and fed through
// utls.Fingerprinter (with AllowBluntMimicry so any extensions utls
// lacks a typed struct for pass through as GenericExtension) into a
// `*utls.ClientHelloSpec`. That spec is what profiles.go injects
// into bogdanfinn/tls-client via a custom `ClientHelloID{SpecFactory:
// ...}`, replacing the library's built-in Chrome_NNN.
//
// To regenerate after a chromium bump:
//
//	go run ./cmd/capture-fingerprint \
//	    -out internal/proxy/fingerprints/chrome146.clienthello.hex
//
// The `tls_fingerprint_ci` integration test compares the spec
// produced from this hex against a fresh chromium on the same host
// and fails CI if they drift.
package fingerprints

import (
	"encoding/hex"
	_ "embed"
	"fmt"
	"strings"
	"sync"

	utls "github.com/bogdanfinn/utls"
)

//go:embed chrome146.clienthello.hex
var chrome146Hex string

var (
	chrome146Once sync.Once
	chrome146Spec *utls.ClientHelloSpec
	chrome146Err  error
)

// Chrome146 returns the captured ClientHelloSpec for Chromium /
// Google Chrome 146. The spec is loaded lazily on first call and
// cached for the lifetime of the process. Returns (nil, err) if the
// committed hex file is corrupt or unparseable.
func Chrome146() (*utls.ClientHelloSpec, error) {
	chrome146Once.Do(func() {
		raw, err := hex.DecodeString(strings.TrimSpace(chrome146Hex))
		if err != nil {
			chrome146Err = fmt.Errorf("fingerprints: decode chrome146 hex: %w", err)
			return
		}
		f := &utls.Fingerprinter{AllowBluntMimicry: true}
		spec, err := f.FingerprintClientHello(raw)
		if err != nil {
			chrome146Err = fmt.Errorf("fingerprints: parse chrome146 ClientHello: %w", err)
			return
		}
		chrome146Spec = spec
	})
	return chrome146Spec, chrome146Err
}

// MustChrome146 is like Chrome146 but panics on error. Intended for
// use at program startup where a corrupt committed hex is a
// programmer error, not a runtime condition.
func MustChrome146() *utls.ClientHelloSpec {
	spec, err := Chrome146()
	if err != nil {
		panic(err)
	}
	return spec
}
