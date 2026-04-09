// Tunnel bindings with in-flight connection counters.
//
// A tunnelBinding wraps a liveTunnel and tracks how many connections
// are currently using it. When a binding is "retiring" (another binding
// has taken over as current), the reaper loop closes it once inflight
// reaches zero, or after MaxRetireAge as a backstop against leaked
// counters.
//
// countingConn wraps every net.Conn returned by the dialer so that
// Close() decrements the binding's counter. The CompareAndSwap on
// closedOnce makes double-close safe.
package rotator

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/onnimonni/fauxbrowser/internal/proton"
	"github.com/onnimonni/fauxbrowser/internal/wgtunnel"
)

// liveTunnel is the subset of *wgtunnel.Tunnel the rotator needs. It
// exists so tests can inject a fake without bringing up a real netstack.
// *wgtunnel.Tunnel already satisfies this interface — see
// defaultTunneler below.
type liveTunnel interface {
	ContextDialer() proxy.ContextDialer
	Config() *wgtunnel.Config
	WaitHandshake(ctx context.Context, deadline time.Duration) error
	Close() error
}

// tunneler starts liveTunnels. Default impl delegates to wgtunnel.Start.
type tunneler interface {
	Start(*wgtunnel.Config) (liveTunnel, error)
}

type defaultTunneler struct{}

func (defaultTunneler) Start(cfg *wgtunnel.Config) (liveTunnel, error) {
	return wgtunnel.Start(cfg, nil)
}

// tunnelBinding is one live WireGuard tunnel with bookkeeping for the
// blue/green rotator state machine.
type tunnelBinding struct {
	tun       liveTunnel
	server    proton.Server
	createdAt time.Time

	inflight  atomic.Int32 // conns dialed via this binding, not yet Closed
	retiring  atomic.Bool  // set by rotate() when another binding takes over
	retiredAt atomic.Int64 // unix nanos — used by reaper's force-close backstop
}

// dial opens a connection through this binding's tunnel and wraps it
// so binding.inflight decrements on Close().
func (b *tunnelBinding) dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := b.tun.ContextDialer().DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	b.inflight.Add(1)
	return &countingConn{Conn: conn, binding: b}, nil
}

// countingConn wraps a net.Conn so Close decrements binding.inflight
// exactly once.
type countingConn struct {
	net.Conn
	binding    *tunnelBinding
	closedOnce atomic.Bool
}

func (c *countingConn) Close() error {
	if c.closedOnce.CompareAndSwap(false, true) {
		c.binding.inflight.Add(-1)
	}
	return c.Conn.Close()
}
