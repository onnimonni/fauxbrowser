// Package wgtunnel embeds a userspace WireGuard tunnel (wireguard-go +
// gVisor netstack) so a single binary can egress via WireGuard without
// a gluetun sidecar, /dev/net/tun, or NET_ADMIN.
//
// The tunnel exposes a proxy.ContextDialer whose connections go through
// the WG peer. Hand that dialer to tls-client (via WithProxyDialerFactory)
// and every upstream fetch silently uses the VPN without any other
// plumbing.
//
// Peer pinning: the WireGuard handshake is itself a proof that the
// server on the other end holds the expected private key, so setting
// PeerPublicKey is peer pinning. There is no auxiliary verification
// needed — a wrong pubkey simply produces no handshake response.
package wgtunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Config describes the subset of a WireGuard .conf fauxbrowser needs.
type Config struct {
	PrivateKey        []byte // 32-byte raw key
	Addresses         []netip.Addr
	DNS               []netip.Addr
	MTU               int
	PeerPublicKey     []byte // 32-byte raw key
	PeerPresharedKey  []byte // 32-byte raw key, optional
	EndpointHost      string
	EndpointPort      int
	PersistentKeepAlv int // seconds, 0 = disabled
}

// Tunnel is a running userspace WireGuard instance. Close when done.
type Tunnel struct {
	device *device.Device
	net    *netstack.Net
	cfg    *Config
}

// LoadConfig parses a WireGuard-style .conf file. Supports only the
// [Interface] + first [Peer] sections; extra peers are ignored.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parseConfig(string(data))
}

// ConfigFromPrivateKey builds a minimal Config from just a base64
// WireGuard private key. The interface address, DNS, MTU, and
// PersistentKeepalive are defaulted to ProtonVPN's published values
// (10.2.0.2/32, 10.2.0.1, 1420, 25s). Peer fields are left empty so
// the rotator can fill them in from the catalog.
//
// This is the gluetun-style entry point: a single WIREGUARD_PRIVATE_KEY
// env var is enough, no .conf file needed.
//
// Note: PersistentKeepalive=25 is critical even though it isn't
// strictly required by the WireGuard handshake itself. Proton's free
// pool sits behind aggressive NAT/CGNAT timeouts; without keepalive,
// userspace wireguard-go's UDP socket can be silently mapped to a
// different external port between handshake initiation and response,
// causing systematic handshake failures across the pool.
func ConfigFromPrivateKey(privateKeyB64 string) (*Config, error) {
	b, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil || len(b) != 32 {
		return nil, errors.New("bad PrivateKey: must be 32-byte base64")
	}
	return &Config{
		PrivateKey: b,
		Addresses:  []netip.Addr{netip.MustParseAddr("10.2.0.2")},
		// Primary: ProtonVPN internal DNS (inside the tunnel).
		// Fallbacks: Cloudflare and Google DNS, also routed through the
		// WireGuard tunnel (AllowedIPs = 0.0.0.0/0). These activate when
		// the ProtonVPN server's internal DNS (10.2.0.1) is unreachable
		// or overloaded — a known failure mode on some free servers.
		DNS: []netip.Addr{
			netip.MustParseAddr("10.2.0.1"),
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("8.8.8.8"),
		},
		MTU:               1420,
		PersistentKeepAlv: 25,
	}, nil
}

func parseConfig(text string) (*Config, error) {
	cfg := &Config{MTU: 1420}
	section := ""
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				b, err := base64.StdEncoding.DecodeString(val)
				if err != nil || len(b) != 32 {
					return nil, errors.New("bad PrivateKey")
				}
				cfg.PrivateKey = b
			case "address":
				for _, a := range splitCSV(val) {
					ap, err := netip.ParsePrefix(a)
					if err != nil {
						if ip, err2 := netip.ParseAddr(a); err2 == nil {
							cfg.Addresses = append(cfg.Addresses, ip)
							continue
						}
						return nil, fmt.Errorf("bad Address %q: %w", a, err)
					}
					cfg.Addresses = append(cfg.Addresses, ap.Addr())
				}
			case "dns":
				for _, s := range splitCSV(val) {
					ip, err := netip.ParseAddr(s)
					if err != nil {
						return nil, fmt.Errorf("bad DNS %q: %w", s, err)
					}
					cfg.DNS = append(cfg.DNS, ip)
				}
			case "mtu":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("bad MTU: %w", err)
				}
				cfg.MTU = n
			}
		case "peer":
			switch key {
			case "publickey":
				b, err := base64.StdEncoding.DecodeString(val)
				if err != nil || len(b) != 32 {
					return nil, errors.New("bad PublicKey")
				}
				cfg.PeerPublicKey = b
			case "presharedkey":
				if val == "" {
					continue
				}
				b, err := base64.StdEncoding.DecodeString(val)
				if err != nil || len(b) != 32 {
					return nil, errors.New("bad PresharedKey")
				}
				cfg.PeerPresharedKey = b
			case "endpoint":
				host, portStr, err := net.SplitHostPort(val)
				if err != nil {
					return nil, fmt.Errorf("bad Endpoint %q: %w", val, err)
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return nil, fmt.Errorf("bad Endpoint port %q: %w", portStr, err)
				}
				if ip := net.ParseIP(host); ip != nil {
					cfg.EndpointHost = host
				} else {
					ips, err := net.LookupHost(host)
					if err != nil || len(ips) == 0 {
						return nil, fmt.Errorf("resolve Endpoint %q: %w", host, err)
					}
					cfg.EndpointHost = ips[0]
				}
				cfg.EndpointPort = port
			case "persistentkeepalive":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("bad PersistentKeepalive: %w", err)
				}
				cfg.PersistentKeepAlv = n
			}
		}
	}
	if len(cfg.PrivateKey) == 0 {
		return nil, errors.New("PrivateKey missing")
	}
	if len(cfg.PeerPublicKey) == 0 {
		return nil, errors.New("Peer PublicKey missing")
	}
	if cfg.EndpointHost == "" {
		return nil, errors.New("Peer Endpoint missing")
	}
	if len(cfg.Addresses) == 0 {
		return nil, errors.New("Interface Address missing")
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = []netip.Addr{netip.MustParseAddr("10.2.0.1")}
	}
	return cfg, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// WithPeer returns a copy of c with a new peer public key and endpoint,
// preserving everything else (notably the private key and interface
// address). Used by the rotator to swap exits without rebuilding
// interface state from scratch.
func (c *Config) WithPeer(peerPubkeyBase64, endpointIP string, port int) (*Config, error) {
	pub, err := base64.StdEncoding.DecodeString(peerPubkeyBase64)
	if err != nil || len(pub) != 32 {
		return nil, fmt.Errorf("bad peer public key %q", peerPubkeyBase64)
	}
	if net.ParseIP(endpointIP) == nil {
		return nil, fmt.Errorf("peer endpoint %q is not a literal IP (must be resolved before this call)", endpointIP)
	}
	if port <= 0 {
		port = 51820
	}
	cp := *c
	cp.PeerPublicKey = pub
	cp.PeerPresharedKey = nil
	cp.EndpointHost = endpointIP
	cp.EndpointPort = port
	return &cp, nil
}

// PeerPublicKeyBase64 returns the current peer public key, base64-encoded.
func (c *Config) PeerPublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(c.PeerPublicKey)
}

// Start brings up a userspace WireGuard tunnel for the given config and
// returns a live Tunnel.
func Start(cfg *Config, logf func(format string, args ...any)) (*Tunnel, error) {
	tun, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack TUN: %w", err)
	}
	if logf == nil {
		logf = func(format string, args ...any) {}
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(format string, args ...any) { logf("wg: "+format, args...) },
		Errorf:   func(format string, args ...any) { logf("wg: "+format, args...) },
	})
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey))
	fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(cfg.PeerPublicKey))
	if len(cfg.PeerPresharedKey) > 0 {
		fmt.Fprintf(&sb, "preshared_key=%s\n", hex.EncodeToString(cfg.PeerPresharedKey))
	}
	fmt.Fprintf(&sb, "endpoint=%s:%d\n", cfg.EndpointHost, cfg.EndpointPort)
	fmt.Fprintf(&sb, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&sb, "allowed_ip=::/0\n")
	if cfg.PersistentKeepAlv > 0 {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", cfg.PersistentKeepAlv)
	}
	if err := dev.IpcSet(sb.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg device up: %w", err)
	}
	return &Tunnel{device: dev, net: tnet, cfg: cfg}, nil
}

// WaitHandshake polls the device IPC until the peer reports a recent
// handshake, or the deadline expires. Returns nil on success. Used by
// the rotator to distinguish a "peer accepted our pubkey" success from
// a silent failure (wrong pinned pubkey = no response forever).
func (t *Tunnel) WaitHandshake(ctx context.Context, deadline time.Duration) error {
	d, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-d.Done():
			return fmt.Errorf("wg handshake not observed within %s", deadline)
		case <-tick.C:
			ipc, err := t.device.IpcGet()
			if err != nil {
				continue
			}
			// Look for a non-zero last_handshake_time_sec line.
			for _, line := range strings.Split(ipc, "\n") {
				if strings.HasPrefix(line, "last_handshake_time_sec=") {
					if strings.TrimPrefix(line, "last_handshake_time_sec=") != "0" {
						return nil
					}
				}
			}
		}
	}
}

// Close tears down the tunnel.
func (t *Tunnel) Close() error {
	t.device.Close()
	return nil
}

// Config returns the tunnel's live config.
func (t *Tunnel) Config() *Config { return t.cfg }

// ContextDialer returns a proxy.ContextDialer whose connections egress
// via the WireGuard tunnel.
func (t *Tunnel) ContextDialer() proxy.ContextDialer {
	return &wgDialer{net: t.net}
}

type wgDialer struct{ net *netstack.Net }

func (d *wgDialer) Dial(network, address string) (net.Conn, error) {
	return d.net.Dial(network, address)
}

func (d *wgDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.net.DialContext(ctx, network, address)
}
