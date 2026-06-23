package wgtunnel

import (
	"strings"
	"testing"
)

func TestParseConfigMinimal(t *testing.T) {
	conf := `
[Interface]
PrivateKey = lb7bveAqoEQlELeAQxUclA8AvIoOO3ZnjuXMV1V3+io=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = sxvlBotEqcKIhj6s6aW+hoKckTf0DPEFJkg99nrQ534=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.1:51820
PersistentKeepalive = 25
`
	cfg, err := parseConfig(conf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.PrivateKey) != 32 {
		t.Errorf("PrivateKey len = %d, want 32", len(cfg.PrivateKey))
	}
	if len(cfg.PeerPublicKey) != 32 {
		t.Errorf("PeerPublicKey len = %d, want 32", len(cfg.PeerPublicKey))
	}
	if cfg.EndpointHost != "192.0.2.1" {
		t.Errorf("Endpoint = %q, want 192.0.2.1", cfg.EndpointHost)
	}
	if cfg.EndpointPort != 51820 {
		t.Errorf("EndpointPort = %d, want 51820", cfg.EndpointPort)
	}
	if len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "10.2.0.2" {
		t.Errorf("Addresses = %v, want [10.2.0.2]", cfg.Addresses)
	}
	// normalizeForNetstack keeps the conf's IPv4 resolver and always appends
	// the Cloudflare/Google IPv4 fallbacks (gVisor-safe resolution).
	if len(cfg.DNS) != 3 ||
		cfg.DNS[0].String() != "10.2.0.1" ||
		cfg.DNS[1].String() != "1.1.1.1" ||
		cfg.DNS[2].String() != "8.8.8.8" {
		t.Errorf("DNS = %v, want [10.2.0.1 1.1.1.1 8.8.8.8]", cfg.DNS)
	}
	if cfg.PersistentKeepAlv != 25 {
		t.Errorf("PersistentKeepalive = %d, want 25", cfg.PersistentKeepAlv)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU default = %d, want 1420", cfg.MTU)
	}
}

// A real ProtonVPN .conf carries IPv6 interface address + IPv6 DNS, which the
// gVisor netstack can't resolve over (UDP/IPv6) — normalizeForNetstack must
// strip them so requests don't 502 on DNS timeouts.
func TestParseConfigDropsIPv6(t *testing.T) {
	conf := `
[Interface]
PrivateKey = lb7bveAqoEQlELeAQxUclA8AvIoOO3ZnjuXMV1V3+io=
Address = 10.2.0.2/32, 2a07:b944::2:2/128
DNS = 10.2.0.1, 2a07:b944::2:1
[Peer]
PublicKey = sxvlBotEqcKIhj6s6aW+hoKckTf0DPEFJkg99nrQ534=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.1:51820
`
	cfg, err := parseConfig(conf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, a := range cfg.Addresses {
		if !a.Is4() {
			t.Errorf("IPv6 interface address survived: %v", cfg.Addresses)
		}
	}
	for _, d := range cfg.DNS {
		if !d.Is4() {
			t.Errorf("IPv6 DNS resolver survived: %v", cfg.DNS)
		}
	}
	if len(cfg.DNS) != 3 { // 10.2.0.1 + 1.1.1.1 + 8.8.8.8
		t.Errorf("DNS = %v, want IPv4 Proton + 2 fallbacks", cfg.DNS)
	}
}

func TestParseConfigRejectsBadKey(t *testing.T) {
	cases := map[string]string{
		"missing private key": "[Interface]\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = sxvlBotEqcKIhj6s6aW+hoKckTf0DPEFJkg99nrQ534=\nEndpoint = 1.2.3.4:5\n",
		"missing endpoint":    "[Interface]\nPrivateKey = lb7bveAqoEQlELeAQxUclA8AvIoOO3ZnjuXMV1V3+io=\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = sxvlBotEqcKIhj6s6aW+hoKckTf0DPEFJkg99nrQ534=\n",
		"bad b64 key":         "[Interface]\nPrivateKey = not-base64!!\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = sxvlBotEqcKIhj6s6aW+hoKckTf0DPEFJkg99nrQ534=\nEndpoint = 1.2.3.4:5\n",
	}
	for name, conf := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(conf); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestParseConfigCommentsAndBlanks(t *testing.T) {
	conf := `
# comment
[Interface]
# another comment
PrivateKey = lb7bveAqoEQlELeAQxUclA8AvIoOO3ZnjuXMV1V3+io=
Address = 10.2.0.2/32

[Peer]
# peer comment
PublicKey = sxvlBotEqcKIhj6s6aW+hoKckTf0DPEFJkg99nrQ534=
Endpoint = 192.0.2.1:51820
`
	cfg, err := parseConfig(conf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasPrefix(cfg.EndpointHost, "192.") {
		t.Errorf("endpoint = %q", cfg.EndpointHost)
	}
}
