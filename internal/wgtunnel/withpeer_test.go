package wgtunnel

import (
	"encoding/base64"
	"testing"
)

func TestWithPeer(t *testing.T) {
	base := &Config{
		PrivateKey: mustB64("lb7bveAqoEQlELeAQxUclA8AvIoOO3ZnjuXMV1V3+io="),
	}
	newPub := "UIV6mDfDCun6PrjT7kFrpl02eEwqIa/piXoSKm1ybBU="
	got, err := base.WithPeer(newPub, "89.39.107.113", 51820)
	if err != nil {
		t.Fatalf("WithPeer: %v", err)
	}
	if got.EndpointHost != "89.39.107.113" {
		t.Errorf("EndpointHost = %q", got.EndpointHost)
	}
	if got.EndpointPort != 51820 {
		t.Errorf("EndpointPort = %d", got.EndpointPort)
	}
	if got.PeerPublicKeyBase64() != newPub {
		t.Errorf("PeerPublicKeyBase64 = %q, want %q", got.PeerPublicKeyBase64(), newPub)
	}
	// Base must not be mutated.
	if base.EndpointHost != "" {
		t.Errorf("base EndpointHost was mutated: %q", base.EndpointHost)
	}
}

func TestWithPeerRejectsHostname(t *testing.T) {
	base := &Config{PrivateKey: mustB64("lb7bveAqoEQlELeAQxUclA8AvIoOO3ZnjuXMV1V3+io=")}
	_, err := base.WithPeer("UIV6mDfDCun6PrjT7kFrpl02eEwqIa/piXoSKm1ybBU=", "not-an-ip", 51820)
	if err == nil {
		t.Errorf("expected error for hostname endpoint")
	}
}

func TestWithPeerRejectsBadPubkey(t *testing.T) {
	base := &Config{PrivateKey: mustB64("lb7bveAqoEQlELeAQxUclA8AvIoOO3ZnjuXMV1V3+io=")}
	_, err := base.WithPeer("not-base64!!", "1.2.3.4", 51820)
	if err == nil {
		t.Errorf("expected error for bad pubkey")
	}
}

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
