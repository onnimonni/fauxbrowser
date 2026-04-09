package rotator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/onnimonni/fauxbrowser/internal/proton"
	"github.com/onnimonni/fauxbrowser/internal/wgtunnel"
)

// --- fake tunneler / liveTunnel -------------------------------------------
//
// fakeTunneler hands out fakeTunnel instances. Tests control success/
// failure of each Start, WaitHandshake, and probe via flags on the
// fake. The fakeTunnel's ContextDialer returns fakeConns that never
// actually hit the network — they're tracked by the binding for the
// in-flight counter.

type fakeTunneler struct {
	mu        sync.Mutex
	started   []*fakeTunnel
	startErr  error
	nextIndex int // index of the next fake to hand out
}

func (f *fakeTunneler) Start(cfg *wgtunnel.Config) (liveTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return nil, f.startErr
	}
	ft := &fakeTunnel{cfg: cfg, index: f.nextIndex}
	f.nextIndex++
	f.started = append(f.started, ft)
	return ft, nil
}

type fakeTunnel struct {
	cfg          *wgtunnel.Config
	index        int
	handshakeErr error
	closed       atomic.Bool
}

func (f *fakeTunnel) ContextDialer() proxy.ContextDialer {
	return &fakeDialer{t: f}
}
func (f *fakeTunnel) Config() *wgtunnel.Config { return f.cfg }
func (f *fakeTunnel) WaitHandshake(ctx context.Context, d time.Duration) error {
	return f.handshakeErr
}
func (f *fakeTunnel) Close() error {
	f.closed.Store(true)
	return nil
}

type fakeDialer struct{ t *fakeTunnel }

func (d *fakeDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.t.closed.Load() {
		return nil, errors.New("fake tunnel closed")
	}
	a, b := net.Pipe()
	go func() { <-ctx.Done(); _ = a.Close() }()
	// Return b; the caller (binding.dial) will wrap it.
	go func() {
		// Drain a so writes from the caller don't block.
		buf := make([]byte, 4096)
		for {
			if _, err := a.Read(buf); err != nil {
				return
			}
		}
	}()
	return b, nil
}

// --- fake catalog + pool helpers ------------------------------------------
//
// Build a proton.Catalog + proton.Pool backed by in-memory servers so
// tests don't touch the embedded snapshot.

func buildTestPool(t *testing.T, servers []proton.Server) (*proton.Catalog, *proton.Pool) {
	t.Helper()
	// proton.Catalog's fields are unexported, so we go through the
	// embedded snapshot path by writing a temp snapshot. But that's
	// invasive. Simpler: use the Embedded catalog and overlay the
	// ExpectedPubkey map indirectly by reusing real IPs. For the
	// state-machine tests we only need:
	//   - Catalog.ExpectedPubkey(ip) to return the right pubkey for
	//     each fake server
	//   - Pool.Next / Pool.Taint / Pool.Size / Pool.Available
	// Since we can't construct a Catalog from outside the package,
	// use the real Embedded one and pick real servers from it for
	// our fakes.
	real, err := proton.Embedded()
	if err != nil {
		t.Fatalf("load embedded catalog: %v", err)
	}
	// Pick real entries so ExpectedPubkey lookups succeed.
	nl := real.Filter(proton.TierFreeOnly, []string{"NL"}, nil)
	if len(nl) < len(servers) {
		t.Fatalf("embedded catalog has only %d NL servers, need %d for test", len(nl), len(servers))
	}
	out := make([]proton.Server, len(servers))
	for i := range servers {
		out[i] = nl[i]
	}
	pool := proton.NewPool(out, 60, nil)
	return real, pool
}

// --- test helper: build a rotator ready for state-machine tests -----------

func newTestRotator(t *testing.T, ft *fakeTunneler) *Rotator {
	t.Helper()
	cat, pool := buildTestPool(t, make([]proton.Server, 6))
	r := New(Options{
		BaseConfig: &wgtunnel.Config{
			PrivateKey: make([]byte, 32),
		},
		Catalog:           cat,
		Pool:              pool,
		HandshakeTimeout:  200 * time.Millisecond,
		MinHostRotation:   500 * time.Millisecond, // short for tests
		GlobalMinInterval: 1 * time.Millisecond,
		MaxRetireAge:      2 * time.Second,
		ReaperInterval:    100 * time.Millisecond,
		Tunneler:          ft,
		ProbeFn: func(ctx context.Context, tun liveTunnel, d time.Duration) error {
			return nil // always succeeds in tests
		},
		Logf: func(msg string, args ...any) {}, // silent
	})
	return r
}

// --- tests ----------------------------------------------------------------

func TestBlueGreenHappyPath(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotator(t, ft)
	defer r.Close()

	ctx := context.Background()
	if err := r.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	initial := r.current.Load()
	if initial == nil {
		t.Fatalf("no current binding after bootstrap")
	}

	// Simulate a 429 on host A.
	fired, _ := r.RotateIfTriggered("example.com", 429, http.Header{})
	if !fired {
		t.Fatalf("RotateIfTriggered should have fired on 429")
	}

	// Wait for the rotation goroutine to complete.
	waitFor(t, 2*time.Second, func() bool {
		return r.rotations.Load() >= 2
	})

	after := r.current.Load()
	if after == initial {
		t.Errorf("current binding didn't change after rotation")
	}
	// Old binding should be retiring.
	if !initial.retiring.Load() {
		t.Errorf("old binding not marked retiring")
	}
}

func TestHostQuarantineBlocksSameHostDials(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotator(t, ft)
	defer r.Close()

	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// Manually quarantine host A without firing the real rotation so
	// we can observe the gate behavior deterministically.
	r.hostsMu.Lock()
	hs := &hostState{}
	r.hosts["blocked.example"] = hs
	r.hostsMu.Unlock()
	hs.mu.Lock()
	hs.quarantined = true
	hs.ready = make(chan struct{})
	hs.lastRotationAt = time.Now()
	gate := hs.ready
	hs.mu.Unlock()

	// Dial to the quarantined host should block until the gate closes.
	dialer := r.Dialer()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err := dialer.DialContext(ctx, "tcp", "blocked.example:443")
		done <- err
	}()
	select {
	case <-done:
		t.Fatalf("dial returned before quarantine was lifted")
	case <-time.After(80 * time.Millisecond):
		// good — still blocked
	}

	// Dial to a different host should proceed immediately.
	fastDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", "other.example:443")
		if conn != nil {
			_ = conn.Close()
		}
		fastDone <- err
	}()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Errorf("non-quarantined host dial failed: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("non-quarantined host dial timed out")
	}

	// Lift the quarantine.
	hs.mu.Lock()
	hs.quarantined = false
	close(gate)
	hs.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("quarantined-host dial failed after release: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("quarantined-host dial did not resume after release")
	}
}

func TestPerHostDebounce(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotator(t, ft)
	defer r.Close()

	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// First 429 → rotation fires.
	fired1, _ := r.RotateIfTriggered("api.example", 429, http.Header{})
	if !fired1 {
		t.Fatalf("first 429 should fire rotation")
	}
	waitFor(t, 2*time.Second, func() bool { return r.rotations.Load() >= 2 })

	// Second 429 on the SAME host within MinHostRotation → debounced.
	fired2, reason := r.RotateIfTriggered("api.example", 429, http.Header{})
	if fired2 {
		t.Errorf("second 429 on same host should be debounced")
	}
	if reason != "debounced" {
		t.Errorf("reason = %q, want debounced", reason)
	}

	// 429 on a DIFFERENT host → should still fire.
	fired3, _ := r.RotateIfTriggered("other.example", 429, http.Header{})
	if !fired3 {
		t.Errorf("429 on different host should still fire")
	}
}

func TestRetirementDrainsOnZeroInflight(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotator(t, ft)
	defer r.Close()

	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	old := r.current.Load()

	// Force rotation. Old binding should become retiring.
	if err := r.ForceRotate(context.Background()); err != nil {
		t.Fatalf("force rotate: %v", err)
	}
	if !old.retiring.Load() {
		t.Fatalf("old binding not retiring after rotate")
	}

	// No in-flight connections → reaper should close it within a few
	// ticks.
	waitFor(t, 2*time.Second, func() bool {
		ft.mu.Lock()
		defer ft.mu.Unlock()
		if len(ft.started) < 2 {
			return false
		}
		return ft.started[0].closed.Load()
	})
}

func TestRetirementForceCloseAfterMaxRetireAge(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotator(t, ft)
	// Override MaxRetireAge to something very short for this test.
	r.opts.MaxRetireAge = 150 * time.Millisecond
	defer r.Close()

	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	oldBinding := r.current.Load()
	// Simulate a stuck in-flight counter that never decrements.
	oldBinding.inflight.Store(1)

	if err := r.ForceRotate(context.Background()); err != nil {
		t.Fatalf("force rotate: %v", err)
	}

	// Within MaxRetireAge + 2 * ReaperInterval the reaper must
	// force-close the stuck binding.
	waitFor(t, 2*time.Second, func() bool {
		return ft.started[0].closed.Load()
	})
}

func TestConcurrentBurstCollapsesToOneRotation(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotator(t, ft)
	defer r.Close()

	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Make the second rotation take long enough that the debounce
	// window for "same host" collapses concurrent attempts.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.RotateIfTriggered("busy.example", 429, http.Header{})
		}()
	}
	wg.Wait()

	// Wait for any in-flight rotation goroutine to complete.
	waitFor(t, 2*time.Second, func() bool {
		return r.rotations.Load() >= 2
	})

	// Exactly 2 tunnels should have been started: bootstrap + one
	// rotation. NOT 51.
	ft.mu.Lock()
	n := len(ft.started)
	ft.mu.Unlock()
	if n > 3 {
		t.Errorf("expected ≤3 tunnels (bootstrap + one rotation + maybe one race), got %d", n)
	}
}

func TestRotationFailureExhaustsPool(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotator(t, ft)
	// Override probe to always fail.
	r.opts.ProbeFn = func(ctx context.Context, tun liveTunnel, d time.Duration) error {
		return errors.New("simulated probe failure")
	}
	defer r.Close()

	err := r.Bootstrap(context.Background())
	if err == nil {
		t.Fatalf("Bootstrap should fail when every candidate fails probe")
	}
}

// waitFor polls pred() every 20ms until it returns true or the deadline
// expires, then fails the test if still false.
func waitFor(t *testing.T, deadline time.Duration, pred func() bool) {
	t.Helper()
	start := time.Now()
	for time.Since(start) < deadline {
		if pred() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("waitFor timed out after %s", deadline)
}

// fmt used by one of the logf stubs; prevent unused-import.
var _ = fmt.Sprintf
