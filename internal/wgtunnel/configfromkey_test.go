package wgtunnel

import (
	"testing"
)

func TestConfigFromPrivateKey(t *testing.T) {
	cfg, err := ConfigFromPrivateKey("lb7bveAqoEQlELeAQxUclA8AvIoOO3ZnjuXMV1V3+io=")
	if err != nil {
		t.Fatalf("ConfigFromPrivateKey: %v", err)
	}
	if len(cfg.PrivateKey) != 32 {
		t.Errorf("PrivateKey len = %d, want 32", len(cfg.PrivateKey))
	}
	if len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "10.2.0.2" {
		t.Errorf("Addresses = %v, want [10.2.0.2]", cfg.Addresses)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0].String() != "10.2.0.1" {
		t.Errorf("DNS = %v, want [10.2.0.1]", cfg.DNS)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", cfg.MTU)
	}
	if len(cfg.PeerPublicKey) != 0 || cfg.EndpointHost != "" {
		t.Errorf("peer fields should be empty (rotator fills them in)")
	}
}

func TestConfigFromPrivateKeyRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"", "not-base64!!", "dG9vc2hvcnQ=" /* 8 bytes */} {
		t.Run(bad, func(t *testing.T) {
			if _, err := ConfigFromPrivateKey(bad); err == nil {
				t.Errorf("expected error for %q", bad)
			}
		})
	}
}
