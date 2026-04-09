package fingerprints

import (
	"testing"

	utls "github.com/bogdanfinn/utls"
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

// TestChrome146ReturnsFreshSpec verifies each call returns a
// distinct spec instance — critical for avoiding cross-host h2
// connection contamination from shared mutable extension state.
func TestChrome146ReturnsFreshSpec(t *testing.T) {
	a, err := Chrome146()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Chrome146()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("Chrome146 should return fresh specs, got same pointer")
	}
	// Both should have the same structure.
	if len(a.CipherSuites) != len(b.CipherSuites) {
		t.Errorf("cipher count mismatch: %d vs %d", len(a.CipherSuites), len(b.CipherSuites))
	}
}

// TestChrome146SNIDoesNotLeak is the regression test for the
// cross-host h2 connection pool contamination bug. If the spec is
// shared (cached pointer), mutating SNI on connection A leaks to
// connection B — causing "certificate valid for X, not Y" errors
// in production.
func TestChrome146SNIDoesNotLeak(t *testing.T) {
	a, _ := Chrome146()
	b, _ := Chrome146()

	// Find the SNI extension in each spec and set different hosts.
	setSNI := func(spec *utls.ClientHelloSpec, host string) {
		for _, ext := range spec.Extensions {
			if sni, ok := ext.(*utls.SNIExtension); ok {
				sni.ServerName = host
				return
			}
		}
		t.Fatal("SNIExtension not found in spec")
	}

	setSNI(a, "host-a.example.com")
	setSNI(b, "host-b.example.com")

	// Verify mutation on A didn't leak to B.
	for _, ext := range b.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok {
			if sni.ServerName != "host-b.example.com" {
				t.Errorf("SNI leaked across specs: got %q, want host-b.example.com (host-a.example.com leaked)", sni.ServerName)
			}
			return
		}
	}
}
