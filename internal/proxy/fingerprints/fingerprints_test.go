package fingerprints

import (
	"testing"
)

// TestChrome146LoadsCleanly verifies the committed hex file is well-
// formed and utls.Fingerprinter can parse it into a spec. A failure
// here means the committed chrome146.clienthello.hex is corrupt —
// regenerate with `go run ./cmd/capture-fingerprint`.
func TestChrome146LoadsCleanly(t *testing.T) {
	spec, err := Chrome146()
	if err != nil {
		t.Fatalf("load Chrome146 spec: %v", err)
	}
	if spec == nil {
		t.Fatal("Chrome146 returned nil spec")
	}
	// Basic sanity: Chrome 146 ships ~15 non-GREASE cipher suites
	// and ~16-17 non-GREASE extensions. After GREASE inclusion the
	// parsed spec has ~16 ciphers and ~18 extensions. Anything
	// dramatically smaller means we lost most of the handshake
	// during capture/parse.
	if len(spec.CipherSuites) < 10 {
		t.Errorf("suspiciously few ciphers: %d (expected ~16)", len(spec.CipherSuites))
	}
	if len(spec.Extensions) < 10 {
		t.Errorf("suspiciously few extensions: %d (expected ~18)", len(spec.Extensions))
	}
	t.Logf("Chrome146 spec: %d ciphers, %d extensions",
		len(spec.CipherSuites), len(spec.Extensions))
}

// TestChrome146Memoized verifies the sync.Once caching works — two
// calls return pointer-equal specs.
func TestChrome146Memoized(t *testing.T) {
	a, err := Chrome146()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Chrome146()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("Chrome146 returned different pointers: %p vs %p", a, b)
	}
}
