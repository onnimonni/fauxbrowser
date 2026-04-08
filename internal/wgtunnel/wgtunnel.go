// Package wgtunnel embeds a userspace WireGuard tunnel (wireguard-go +
// gVisor netstack) inside fauxbrowser so a single binary can egress via
// WireGuard without a gluetun sidecar, /dev/net/tun, or NET_ADMIN.
//
// The tunnel exposes a proxy.ContextDialer whose connections go through
// the WG peer. Hand that dialer to tls-client (via WithProxyDialerFactory)
// and every upstream fetch silently uses the VPN without any other
// plumbing. If nothing else in the binary uses any other Dialer, there
// is no bare-metal IP leak path — the kill switch is architectural
// rather than firewall-based.
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

	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Config describes the subset of a WireGuard .conf fauxbrowser needs.
type Config struct {
	PrivateKey        []byte     // 32-byte raw key
	Addresses         []netip.Addr
	DNS               []netip.Addr
	MTU               int
	PeerPublicKey     []byte     // 32-byte raw key
	PeerPresharedKey  []byte     // 32-byte raw key, optional
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
// Not a full wg-quick parser — intentionally minimal.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parseConfig(string(data))
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
					return nil, fmt.Errorf("bad PrivateKey")
				}
				cfg.PrivateKey = b
			case "address":
				for _, a := range splitCSV(val) {
					ap, err := netip.ParsePrefix(a)
					if err != nil {
						// also accept bare addrs
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
					return nil, fmt.Errorf("bad PublicKey")
				}
				cfg.PeerPublicKey = b
			case "presharedkey":
				if val == "" {
					continue
				}
				b, err := base64.StdEncoding.DecodeString(val)
				if err != nil || len(b) != 32 {
					return nil, fmt.Errorf("bad PresharedKey")
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
				// Endpoint may be a hostname — resolve on the host network
				// (this is intentional: we can't resolve it inside the tunnel
				// before the tunnel is up).
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
		// Sensible fallback; user should set it.
		cfg.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
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

// Start brings up a userspace WireGuard tunnel for the given config and
// returns a live Tunnel.
func Start(cfg *Config, logf func(format string, args ...any)) (*Tunnel, error) {
	tun, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack TUN: %w", err)
	}
	lvl := device.LogLevelError
	if logf == nil {
		logf = func(format string, args ...any) {}
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(format string, args ...any) { logf("wg: "+format, args...) },
		Errorf:   func(format string, args ...any) { logf("wg: "+format, args...) },
	})
	_ = lvl

	// Build the wg IpcSet script. Keys must be hex-encoded.
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey))
	fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(cfg.PeerPublicKey))
	if len(cfg.PeerPresharedKey) > 0 {
		fmt.Fprintf(&sb, "preshared_key=%s\n", hex.EncodeToString(cfg.PeerPresharedKey))
	}
	fmt.Fprintf(&sb, "endpoint=%s:%d\n", cfg.EndpointHost, cfg.EndpointPort)
	// Route everything through the tunnel.
	fmt.Fprintf(&sb, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&sb, "allowed_ip=::/0\n")
	if cfg.PersistentKeepAlv > 0 {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", cfg.PersistentKeepAlv)
	}
	if err := dev.IpcSet(sb.String()); err != nil {
		return nil, fmt.Errorf("wg IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("wg device up: %w", err)
	}
	return &Tunnel{device: dev, net: tnet, cfg: cfg}, nil
}

// Close tears down the tunnel.
func (t *Tunnel) Close() error {
	t.device.Close()
	return nil
}

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
