package wgtunnel

import (
	"strings"
	"testing"
)

func TestParseConfigMinimal(t *testing.T) {
	conf := `
[Interface]
PrivateKey = KJZ9wkH7npHQLJk9AmZvVnsuRELB7tzOkG9MC3p+E2g=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = WTqjxi+neLlaVKk466v+w+LyMWfT+OuKlfbiTkpVdl4=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 185.132.133.79:51820
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
	if cfg.EndpointHost != "185.132.133.79" {
		t.Errorf("Endpoint = %q, want 185.132.133.79", cfg.EndpointHost)
	}
	if cfg.EndpointPort != 51820 {
		t.Errorf("EndpointPort = %d, want 51820", cfg.EndpointPort)
	}
	if len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "10.2.0.2" {
		t.Errorf("Addresses = %v, want [10.2.0.2]", cfg.Addresses)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0].String() != "10.2.0.1" {
		t.Errorf("DNS = %v, want [10.2.0.1]", cfg.DNS)
	}
	if cfg.PersistentKeepAlv != 25 {
		t.Errorf("PersistentKeepalive = %d, want 25", cfg.PersistentKeepAlv)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU default = %d, want 1420", cfg.MTU)
	}
}

func TestParseConfigRejectsBadKey(t *testing.T) {
	cases := map[string]string{
		"missing private key": "[Interface]\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = WTqjxi+neLlaVKk466v+w+LyMWfT+OuKlfbiTkpVdl4=\nEndpoint = 1.2.3.4:5\n",
		"missing endpoint":    "[Interface]\nPrivateKey = KJZ9wkH7npHQLJk9AmZvVnsuRELB7tzOkG9MC3p+E2g=\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = WTqjxi+neLlaVKk466v+w+LyMWfT+OuKlfbiTkpVdl4=\n",
		"bad b64 key":         "[Interface]\nPrivateKey = not-base64!!\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = WTqjxi+neLlaVKk466v+w+LyMWfT+OuKlfbiTkpVdl4=\nEndpoint = 1.2.3.4:5\n",
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
PrivateKey = KJZ9wkH7npHQLJk9AmZvVnsuRELB7tzOkG9MC3p+E2g=
Address = 10.2.0.2/32

[Peer]
# peer comment
PublicKey = WTqjxi+neLlaVKk466v+w+LyMWfT+OuKlfbiTkpVdl4=
Endpoint = 185.132.133.79:51820
`
	cfg, err := parseConfig(conf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasPrefix(cfg.EndpointHost, "185.") {
		t.Errorf("endpoint = %q", cfg.EndpointHost)
	}
}
