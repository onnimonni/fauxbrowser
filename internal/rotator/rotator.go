// Package rotator owns the live WireGuard tunnel(s) and swaps peers
// whenever downstream responses indicate the current exit IP has been
// rate-limited or WAF-challenged.
//
// # Blue/green per-host model
//
// The rotator doesn't do global debounce — it does per-host quarantine
// with in-flight drain:
//
//  1. Host A returns 429/403/503 through the current tunnel T1.
//  2. The rotator flags host A as "quarantined" and fires an async
//     goroutine to build a new tunnel T2. Subsequent dials TO HOST A
//     wait on a channel. Dials to hosts B, C, D keep flowing on T1.
//  3. The rotation goroutine picks a fresh Proton peer, brings up T2
//     (handshake + liveness probe), and swaps current := T2.
//  4. T1 is marked retiring. The reaper closes it once every
//     in-flight connection on it has drained (binding.inflight == 0),
//     or after MaxRetireAge as a backstop.
//  5. Quarantine on host A is lifted; buffered dials wake up and use
//     the new current (T2). All new dials to any host also use T2.
//  6. If host A is rate-limited AGAIN within MinHostRotation, the
//     rotator refuses to spin up a third tunnel. The upstream 429
//     flows through to the proxy's client unchanged. The new tunnel
//     stays live for other hosts.
//
// # In-flight tracking
//
// Each dial goes through tunnelBinding.dial, which increments an
// atomic counter on the binding. The returned net.Conn is wrapped in
// a countingConn that decrements on Close. The reaper loop runs every
// ReaperInterval and closes retiring bindings whose counter has hit 0.
//
// # Testability
//
// The real WireGuard stack is behind the `tunneler`/`liveTunnel`
// interfaces (see binding.go). Tests in rotator_test.go inject a fake
// tunneler + stubbed ProbeFn to drive the state machine without any
// network. See TestBlueGreenHappyPath, TestHostIndependence,
// TestDebounceFailedAgain, TestRetirementDrain, TestConcurrentBurst.
package rotator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/onnimonni/fauxbrowser/internal/proton"
	"github.com/onnimonni/fauxbrowser/internal/wgtunnel"
)

// Options configures the rotator.
type Options struct {
	// BaseConfig carries the WireGuard private key, interface address,
	// DNS, and MTU. Peer fields are ignored — rotator picks them from
	// the Proton catalog.
	BaseConfig *wgtunnel.Config

	// Catalog is the embedded Proton snapshot used to pin peer pubkeys.
	Catalog *proton.Catalog

	// Pool is the working server pool. Must already be tier/country/
	// continent filtered.
	Pool *proton.Pool

	// HandshakeTimeout is the max time to wait for a peer to accept
	// our private key on rotation, and also the timeout used by the
	// default liveness probe.
	HandshakeTimeout time.Duration

	// MinHostRotation is the minimum time between two rotations
	// triggered by the same target host. A rapid burst of 429s from
	// the same host collapses to one rotation; subsequent ones are
	// dropped and the upstream 429 flows through to the client.
	MinHostRotation time.Duration

	// GlobalMinInterval is a backstop floor between any two
	// rotations regardless of host. Set to 0 to disable.
	GlobalMinInterval time.Duration

	// MaxRetireAge is how long a retiring binding is allowed to
	// linger after its inflight counter could not drain. After this
	// the reaper force-closes it.
	MaxRetireAge time.Duration

	// ReaperInterval is how often the reaper scans for retiring
	// bindings.
	ReaperInterval time.Duration

	// Tunneler is injectable for tests. Default: defaultTunneler{}.
	Tunneler tunneler

	// ProbeFn runs after a successful handshake to confirm traffic
	// actually flows (catches Proton tier-level routing drops).
	// Injectable for tests.
	ProbeFn func(ctx context.Context, tun liveTunnel, timeout time.Duration) error

	// OnRotate fires synchronously on every successful swap.
	// fauxbrowser uses it to rebuild the transport's cookie jar.
	OnRotate func()

	// Logf is an optional structured log target. Nil means slog.Info.
	Logf func(msg string, args ...any)
}

// Rotator implements the blue/green per-host quarantine state machine.
type Rotator struct {
	opts Options

	current atomic.Pointer[tunnelBinding]

	allMu sync.Mutex
	all   []*tunnelBinding

	hostsMu sync.Mutex
	hosts   map[string]*hostState

	rotMu     sync.Mutex // serializes actual tunnel creation
	rotations atomic.Uint64
	lastRotAt atomic.Int64 // unix nanos

	closed     atomic.Bool
	reaperStop chan struct{}
	reaperDone chan struct{}
}

// hostState tracks per-host quarantine + debounce.
type hostState struct {
	mu             sync.Mutex
	quarantined    bool
	ready          chan struct{} // closed when the quarantine is lifted
	lastRotationAt time.Time
}

// New constructs a Rotator. It does NOT bring the first tunnel up —
// call Bootstrap() before dispatching traffic.
func New(opts Options) *Rotator {
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 6 * time.Second
	}
	if opts.MinHostRotation <= 0 {
		opts.MinHostRotation = 5 * time.Minute
	}
	if opts.GlobalMinInterval < 0 {
		opts.GlobalMinInterval = 0
	} else if opts.GlobalMinInterval == 0 {
		opts.GlobalMinInterval = 2 * time.Second
	}
	if opts.MaxRetireAge <= 0 {
		opts.MaxRetireAge = 2 * time.Minute
	}
	if opts.ReaperInterval <= 0 {
		opts.ReaperInterval = 5 * time.Second
	}
	if opts.Tunneler == nil {
		opts.Tunneler = defaultTunneler{}
	}
	if opts.ProbeFn == nil {
		opts.ProbeFn = defaultProbe
	}
	if opts.Logf == nil {
		opts.Logf = func(msg string, args ...any) { slog.Info(msg, args...) }
	}
	return &Rotator{
		opts:       opts,
		hosts:      make(map[string]*hostState),
		reaperStop: make(chan struct{}),
		reaperDone: make(chan struct{}),
	}
}

// Bootstrap picks an initial server, brings up the first tunnel, and
// starts the reaper goroutine.
func (r *Rotator) Bootstrap(ctx context.Context) error {
	go r.reaperLoop()
	_, err := r.rotate(ctx, "bootstrap")
	return err
}

// Dialer returns a proxy.ContextDialer that routes through the current
// tunnel, honoring per-host quarantine.
func (r *Rotator) Dialer() proxy.ContextDialer { return &rotDialer{r: r} }

type rotDialer struct{ r *Rotator }

func (d *rotDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *rotDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	// Wait on the per-host gate if quarantined. If the quarantine
	// lifts (or was never set), proceed with the current binding.
	if gate := d.r.hostGate(host); gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	binding := d.r.current.Load()
	if binding == nil {
		return nil, errors.New("rotator: no tunnel available")
	}
	return binding.dial(ctx, network, address)
}

// hostGate returns the <-ready channel if host is currently quarantined,
// or nil if it isn't.
func (r *Rotator) hostGate(host string) <-chan struct{} {
	r.hostsMu.Lock()
	hs, ok := r.hosts[host]
	r.hostsMu.Unlock()
	if !ok {
		return nil
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.quarantined {
		return hs.ready
	}
	return nil
}

// ShouldRotate returns true if the downstream response looks like the
// current exit IP has been rate-limited or WAF-challenged.
//
// Heuristics:
//
//	status == 429  → always (rate limit)
//	status == 503  → only with Cloudflare/challenge marker
//	status == 403  → only with known WAF challenge marker
//
// The transport calls this on every response.
func ShouldRotate(status int, h http.Header) (bool, string) {
	if status == 429 {
		return true, "429 rate limit"
	}
	if status != 403 && status != 503 {
		return false, ""
	}
	if v := h.Get("cf-mitigated"); v != "" {
		return true, "cf-mitigated=" + v
	}
	if strings.Contains(strings.ToLower(h.Get("server")), "cloudflare") {
		return true, "cloudflare " + fmt.Sprint(status)
	}
	if h.Get("x-datadome") != "" || h.Get("x-dd-b") != "" {
		return true, "datadome"
	}
	if h.Get("x-iinfo") != "" || strings.Contains(strings.ToLower(h.Get("server")), "akamai") {
		return true, "akamai/imperva"
	}
	if h.Get("x-sucuri-id") != "" {
		return true, "sucuri"
	}
	// Check Point CloudGuard WAF body-based detection: transport peeks the
	// 403 body and sets this internal header when it matches. Never sent
	// to the upstream target — it's on a synthetic header map.
	if h.Get("X-Checkpoint-Block") != "" {
		return true, "checkpoint-waf"
	}
	return false, ""
}

// RotateIfTriggered is called by the transport after every upstream
// response. If the heuristic matches, it quarantines the given host
// and fires a goroutine to rotate. Returns (fired, reason) for logging.
//
// Per-host debounce: if the same host tripped a rotation within
// MinHostRotation, this call is a no-op — the upstream status flows
// through to the caller unchanged.
func (r *Rotator) RotateIfTriggered(host string, status int, h http.Header) (bool, string) {
	ok, reason := ShouldRotate(status, h)
	if !ok {
		return false, ""
	}
	if host == "" {
		// No host → treat as a global rotation request.
		host = "_global"
	}

	r.hostsMu.Lock()
	hs, existed := r.hosts[host]
	if !existed {
		hs = &hostState{}
		r.hosts[host] = hs
	}
	r.hostsMu.Unlock()

	hs.mu.Lock()
	if !hs.lastRotationAt.IsZero() && time.Since(hs.lastRotationAt) < r.opts.MinHostRotation {
		hs.mu.Unlock()
		r.opts.Logf("rotator: host debounced, upstream status flows through",
			"host", host,
			"status", status,
			"reason", reason)
		return false, "debounced"
	}
	if hs.quarantined {
		// Another goroutine is mid-rotation for the same host.
		hs.mu.Unlock()
		return false, "in-progress"
	}
	hs.quarantined = true
	hs.ready = make(chan struct{})
	hs.lastRotationAt = time.Now()
	gate := hs.ready
	hs.mu.Unlock()

	go func() {
		defer func() {
			hs.mu.Lock()
			hs.quarantined = false
			close(gate)
			hs.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if _, err := r.rotate(ctx, reason+" / "+host); err != nil {
			r.opts.Logf("rotator: rotation failed",
				"host", host, "reason", reason, "err", err.Error())
		}
	}()
	return true, reason
}

// ForceRotate triggers a synchronous, unconditional rotation (admin
// endpoint, tests). Bypasses per-host debounce but still respects the
// pool + probe machinery.
func (r *Rotator) ForceRotate(ctx context.Context) error {
	_, err := r.rotate(ctx, "manual")
	return err
}

// rotate brings up a new tunnel and swaps it into place. Serialized
// via rotMu so at most one tunnel creation runs at a time.
func (r *Rotator) rotate(ctx context.Context, reason string) (*tunnelBinding, error) {
	if r.closed.Load() {
		return nil, errors.New("rotator closed")
	}
	r.rotMu.Lock()
	defer r.rotMu.Unlock()

	// Global min-interval backstop.
	if r.opts.GlobalMinInterval > 0 {
		if lastNs := r.lastRotAt.Load(); lastNs > 0 {
			wait := r.opts.GlobalMinInterval - time.Since(time.Unix(0, lastNs))
			if wait > 0 {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
	}

	var lastErr error
	for attempt := 0; attempt < r.opts.Pool.Size()+1; attempt++ {
		srv, ok := r.opts.Pool.Next()
		if !ok {
			return nil, fmt.Errorf("rotator: no healthy server in pool (last err: %v)", lastErr)
		}
		// Belt-and-suspenders pubkey pin check.
		expected, known := r.opts.Catalog.ExpectedPubkey(srv.EntryIP)
		if !known || expected != srv.Pubkey {
			r.opts.Logf("rotator: rejecting server with untrusted pubkey",
				"entry_ip", srv.EntryIP, "name", srv.Name)
			r.opts.Pool.Taint(srv.EntryIP)
			continue
		}
		newCfg, err := r.opts.BaseConfig.WithPeer(srv.Pubkey, srv.EntryIP, 51820)
		if err != nil {
			r.opts.Pool.Taint(srv.EntryIP)
			lastErr = err
			continue
		}
		r.opts.Logf("rotator: dialing peer",
			"reason", reason,
			"name", srv.Name,
			"country", srv.Country,
			"entry_ip", srv.EntryIP,
			"pubkey_pinned", srv.Pubkey)

		tun, err := r.opts.Tunneler.Start(newCfg)
		if err != nil {
			r.opts.Pool.Taint(srv.EntryIP)
			lastErr = fmt.Errorf("start: %w", err)
			continue
		}
		if err := tun.WaitHandshake(ctx, r.opts.HandshakeTimeout); err != nil {
			r.opts.Logf("rotator: handshake failed — server tainted",
				"name", srv.Name, "entry_ip", srv.EntryIP, "err", err.Error())
			_ = tun.Close()
			r.opts.Pool.Taint(srv.EntryIP)
			lastErr = err
			continue
		}
		if err := r.opts.ProbeFn(ctx, tun, r.opts.HandshakeTimeout); err != nil {
			r.opts.Logf("rotator: liveness probe failed — server tainted",
				"name", srv.Name, "entry_ip", srv.EntryIP, "err", err.Error())
			_ = tun.Close()
			r.opts.Pool.Taint(srv.EntryIP)
			lastErr = err
			continue
		}
		// Success. Register the new binding, swap current, retire old.
		nb := &tunnelBinding{
			tun:       tun,
			server:    srv,
			createdAt: time.Now(),
		}
		r.allMu.Lock()
		r.all = append(r.all, nb)
		r.allMu.Unlock()

		prev := r.current.Swap(nb)
		if prev != nil {
			prev.retiring.Store(true)
			prev.retiredAt.Store(time.Now().UnixNano())
		}
		r.rotations.Add(1)
		r.lastRotAt.Store(time.Now().UnixNano())
		if r.opts.OnRotate != nil {
			r.opts.OnRotate()
		}
		r.opts.Logf("rotator: rotated",
			"reason", reason,
			"name", srv.Name,
			"country", srv.Country,
			"entry_ip", srv.EntryIP,
			"rotations_total", r.rotations.Load())
		return nb, nil
	}
	return nil, fmt.Errorf("rotator: exhausted pool without a working peer (last err: %v)", lastErr)
}

// reaperLoop periodically closes retiring bindings that have drained.
func (r *Rotator) reaperLoop() {
	defer close(r.reaperDone)
	t := time.NewTicker(r.opts.ReaperInterval)
	defer t.Stop()
	for {
		select {
		case <-r.reaperStop:
			return
		case <-t.C:
			r.reapOnce()
		}
	}
}

func (r *Rotator) reapOnce() {
	r.allMu.Lock()
	defer r.allMu.Unlock()
	kept := r.all[:0]
	for _, b := range r.all {
		if !b.retiring.Load() {
			kept = append(kept, b)
			continue
		}
		if b.inflight.Load() == 0 {
			_ = b.tun.Close()
			r.opts.Logf("rotator: retired tunnel drained and closed",
				"entry_ip", b.server.EntryIP, "age", time.Since(b.createdAt).String())
			continue
		}
		retiredAt := time.Unix(0, b.retiredAt.Load())
		if time.Since(retiredAt) > r.opts.MaxRetireAge {
			r.opts.Logf("rotator: force-closing retired tunnel past MaxRetireAge",
				"entry_ip", b.server.EntryIP,
				"inflight", b.inflight.Load(),
				"age", time.Since(b.createdAt).String())
			_ = b.tun.Close()
			continue
		}
		kept = append(kept, b)
	}
	r.all = kept
}

// Stats returns observable counters for /.internal/healthz.
func (r *Rotator) Stats() Stats {
	s := Stats{
		Rotations: r.rotations.Load(),
		LastRotUn: r.lastRotAt.Load(),
		PoolTotal: r.opts.Pool.Size(),
		PoolUsabl: r.opts.Pool.Available(),
	}
	if b := r.current.Load(); b != nil {
		s.CurrentIP = b.server.EntryIP
		s.CurrentPub = b.server.Pubkey
		s.CurrentName = b.server.Name
		s.Inflight = b.inflight.Load()
	}
	r.allMu.Lock()
	s.ActiveTunnels = len(r.all)
	r.allMu.Unlock()
	return s
}

// Stats is a snapshot of rotator state for admin/.internal/healthz.
type Stats struct {
	CurrentIP     string
	CurrentPub    string
	CurrentName   string
	Inflight      int32
	Rotations     uint64
	LastRotUn     int64
	PoolTotal     int
	PoolUsabl     int
	ActiveTunnels int
}

// Close tears down the reaper + every binding we've ever started.
func (r *Rotator) Close() {
	if r.closed.Swap(true) {
		return
	}
	close(r.reaperStop)
	<-r.reaperDone
	r.allMu.Lock()
	for _, b := range r.all {
		_ = b.tun.Close()
	}
	r.all = nil
	r.allMu.Unlock()
	r.current.Store(nil)
}

// defaultProbe is the liveness check: TCP-dial 1.1.1.1:443 through the
// fresh tunnel with a short deadline. Proton enforces tier at the
// routing layer, so a handshake-OK tunnel may still silently drop
// packets — the probe catches this.
//
// Uses an IP literal so a broken tunnel can't confuse "DNS timeout"
// with "routing timeout". See SKILL
// protonvpn-free-key-reuse-and-tier-routing.
func defaultProbe(ctx context.Context, tun liveTunnel, timeout time.Duration) error {
	d, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := tun.ContextDialer().DialContext(d, "tcp", "1.1.1.1:443")
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}
