package rotator

import (
	"context"
	"testing"
	"time"

	"github.com/onnimonni/fauxbrowser/internal/proton"
	"github.com/onnimonni/fauxbrowser/internal/wgtunnel"
)

// buildDistinctPool builds a Pool of exactly n servers with DISTINCT entry
// IPs from the embedded free catalog (NL-only has too few unique IPs — Proton
// lists one server under several names/IPs). The pool is distinct-by-EntryIP,
// so the test pool must be too.
func buildDistinctPool(t *testing.T, n int) (*proton.Catalog, *proton.Pool) {
	t.Helper()
	real, err := proton.Embedded()
	if err != nil {
		t.Fatalf("load embedded catalog: %v", err)
	}
	all := real.Filter(proton.TierFreeOnly, nil, nil)
	seen := map[string]bool{}
	out := make([]proton.Server, 0, n)
	for _, s := range all {
		if s.EntryIP == "" || s.Pubkey == "" || seen[s.EntryIP] {
			continue
		}
		seen[s.EntryIP] = true
		out = append(out, s)
		if len(out) == n {
			break
		}
	}
	if len(out) < n {
		t.Fatalf("embedded free catalog has only %d distinct entry IPs, need %d", len(out), n)
	}
	return real, proton.NewPool(out, 60, nil)
}

// newTestRotatorN is newTestRotator with a configurable pool size + server count.
func newTestRotatorN(t *testing.T, ft *fakeTunneler, poolSize, servers int) *Rotator {
	t.Helper()
	cat, pool := buildDistinctPool(t, servers)
	return New(Options{
		BaseConfig:        &wgtunnel.Config{PrivateKey: make([]byte, 32)},
		Catalog:           cat,
		Pool:              pool,
		HandshakeTimeout:  200 * time.Millisecond,
		MinHostRotation:   500 * time.Millisecond,
		GlobalMinInterval: 1 * time.Millisecond,
		MaxRetireAge:      2 * time.Second,
		ReaperInterval:    50 * time.Millisecond,
		PoolSize:          poolSize,
		Tunneler:          ft,
		ProbeFn:           func(ctx context.Context, tun liveTunnel, d time.Duration) error { return nil },
		Logf:              func(msg string, args ...any) {},
	})
}

func activeExits(r *Rotator) map[string]bool {
	out := map[string]bool{}
	if setp := r.activeSet.Load(); setp != nil {
		for _, b := range *setp {
			out[b.server.EntryIP] = true
		}
	}
	return out
}

func TestPoolFillsToN(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotatorN(t, ft, 4, 6)
	defer r.Close()
	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := r.activeCount(); got != 4 {
		t.Fatalf("activeCount = %d, want 4", got)
	}
	if got := len(activeExits(r)); got != 4 {
		t.Fatalf("distinct exit IPs = %d, want 4 (duplicates leaked into the pool)", got)
	}
}

func TestN1Equivalence(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotatorN(t, ft, 1, 6)
	defer r.Close()
	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := r.activeCount(); got != 1 {
		t.Fatalf("activeCount = %d, want 1", got)
	}
	// pickBinding must return the single current binding.
	if r.pickBinding() != r.current.Load() {
		t.Fatalf("pickBinding != current with N=1")
	}
}

func TestLeastLoadedDispatch(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotatorN(t, ft, 3, 6)
	defer r.Close()
	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	set := *r.activeSet.Load()
	if len(set) != 3 {
		t.Fatalf("want 3 live bindings, got %d", len(set))
	}
	// Load them unevenly; the least-loaded (index 2) must be chosen.
	set[0].inflight.Store(5)
	set[1].inflight.Store(9)
	set[2].inflight.Store(1)
	for i := 0; i < 10; i++ {
		if got := r.pickBinding(); got != set[2] {
			t.Fatalf("pickBinding chose inflight=%d, want the min (1)", got.inflight.Load())
		}
	}
	// Equal load → round-robin should spread across all three.
	for _, b := range set {
		b.inflight.Store(0)
	}
	seen := map[*tunnelBinding]int{}
	for i := 0; i < 30; i++ {
		seen[r.pickBinding()]++
	}
	if len(seen) != 3 {
		t.Fatalf("round-robin tiebreak spread across %d bindings, want 3", len(seen))
	}
}

func TestEjectAndBackfillKeepsN(t *testing.T) {
	ft := &fakeTunneler{}
	r := newTestRotatorN(t, ft, 3, 6)
	defer r.Close()
	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	exits := activeExits(r)
	var burn string
	for ip := range exits {
		burn = ip
		break
	}
	newIP, err := r.SwitchAvoiding(context.Background(), burn)
	if err != nil {
		t.Fatalf("switch: %v", err)
	}
	if newIP == burn {
		t.Fatalf("SwitchAvoiding returned the burned exit %s", burn)
	}
	if r.activeExitSet()[burn] {
		t.Fatalf("burned exit %s still in active set", burn)
	}
	// maintainLoop should backfill to 3 within a few reaper ticks.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.activeCount() == 3 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pool did not backfill to 3 after eject (active=%d)", r.activeCount())
}

func TestSessionCapSettlesBelowTarget(t *testing.T) {
	ft := &fakeTunneler{}
	// Ask for 10 distinct exits from a 6-server pool → can only reach 6.
	r := newTestRotatorN(t, ft, 10, 6)
	defer r.Close()
	if err := r.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap should succeed (settle), got: %v", err)
	}
	if got := r.activeCount(); got != 6 {
		t.Fatalf("settled active = %d, want 6 (all distinct servers)", got)
	}
	// Must not spin: give the maintain loop time, count stays at 6.
	time.Sleep(300 * time.Millisecond)
	if got := r.activeCount(); got != 6 {
		t.Fatalf("active drifted to %d after settle, want stable 6", got)
	}
}
