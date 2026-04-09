package solver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubSolver is a deterministic Solver for tests. It records every
// Solve call and returns a configurable Solution.
type stubSolver struct {
	mu       sync.Mutex
	calls    atomic.Int32
	solveErr error
	cookies  []*http.Cookie
	delay    time.Duration
}

func (s *stubSolver) Solve(ctx context.Context, target *url.URL) (*Solution, error) {
	s.calls.Add(1)
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.solveErr != nil {
		return nil, s.solveErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cookies := make([]*http.Cookie, len(s.cookies))
	copy(cookies, s.cookies)
	return &Solution{
		Cookies:   cookies,
		UserAgent: "TestUA/1.0",
		SolvedAt:  time.Now(),
	}, nil
}

func (s *stubSolver) Name() string  { return "stub" }
func (s *stubSolver) Close() error { return nil }

func TestCacheLookupMissAndStore(t *testing.T) {
	stub := &stubSolver{
		cookies: []*http.Cookie{{Name: "cf_clearance", Value: "abc"}},
	}
	c := NewCache(stub, 5*time.Minute)
	target, _ := url.Parse("https://example.com/")
	exitIP := "1.2.3.4"

	if hit := c.Lookup("example.com", exitIP); hit != nil {
		t.Errorf("expected nil cache miss")
	}
	sol, err := c.LookupOrSolve(context.Background(), target, exitIP)
	if err != nil {
		t.Fatalf("LookupOrSolve: %v", err)
	}
	if sol.Cookie("cf_clearance") != "abc" {
		t.Errorf("cookie not returned")
	}
	if stub.calls.Load() != 1 {
		t.Errorf("solver called %d times, want 1", stub.calls.Load())
	}

	// Second lookup should hit cache.
	sol2, err := c.LookupOrSolve(context.Background(), target, exitIP)
	if err != nil {
		t.Fatalf("second LookupOrSolve: %v", err)
	}
	if sol2 != sol {
		t.Errorf("expected same cached solution pointer")
	}
	if stub.calls.Load() != 1 {
		t.Errorf("solver called %d times after cache hit, want 1", stub.calls.Load())
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	stub := &stubSolver{
		cookies: []*http.Cookie{{Name: "cf_clearance", Value: "abc"}},
	}
	c := NewCache(stub, 100*time.Millisecond)
	now := time.Now()
	c.nowFn = func() time.Time { return now }

	target, _ := url.Parse("https://example.com/")
	_, _ = c.LookupOrSolve(context.Background(), target, "1.2.3.4")

	// Same time → still cached.
	if hit := c.Lookup("example.com", "1.2.3.4"); hit == nil {
		t.Errorf("expected cache hit at t=0")
	}
	// Advance past TTL → expired.
	now = now.Add(200 * time.Millisecond)
	if hit := c.Lookup("example.com", "1.2.3.4"); hit != nil {
		t.Errorf("expected cache miss after TTL")
	}
}

func TestCacheInvalidateExit(t *testing.T) {
	stub := &stubSolver{
		cookies: []*http.Cookie{{Name: "cf_clearance", Value: "abc"}},
	}
	c := NewCache(stub, 5*time.Minute)
	target1, _ := url.Parse("https://a.example/")
	target2, _ := url.Parse("https://b.example/")

	// Solve a + b on exit IP X.
	_, _ = c.LookupOrSolve(context.Background(), target1, "1.1.1.1")
	_, _ = c.LookupOrSolve(context.Background(), target2, "1.1.1.1")
	// Solve a on a DIFFERENT exit IP Y.
	_, _ = c.LookupOrSolve(context.Background(), target1, "2.2.2.2")
	if c.Size() != 3 {
		t.Fatalf("Size = %d, want 3", c.Size())
	}

	dropped := c.InvalidateExit("1.1.1.1")
	if dropped != 2 {
		t.Errorf("InvalidateExit dropped %d, want 2", dropped)
	}
	if c.Size() != 1 {
		t.Errorf("Size after invalidate = %d, want 1", c.Size())
	}
	if hit := c.Lookup("a.example", "2.2.2.2"); hit == nil {
		t.Errorf("entry on the other exit IP should still be cached")
	}
}

func TestCacheConcurrentSolveDeduped(t *testing.T) {
	// 50 goroutines all asking for the same key. With singleflight,
	// the underlying solver should be called exactly ONCE.
	stub := &stubSolver{
		cookies: []*http.Cookie{{Name: "cf_clearance", Value: "abc"}},
		delay:   200 * time.Millisecond, // hold the singleflight slot
	}
	c := NewCache(stub, 5*time.Minute)
	target, _ := url.Parse("https://example.com/")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.LookupOrSolve(context.Background(), target, "1.2.3.4")
			if err != nil {
				t.Errorf("LookupOrSolve: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := stub.calls.Load(); got != 1 {
		t.Errorf("solver called %d times under concurrent burst, want 1", got)
	}
}

func TestCacheSolveErrorNotCached(t *testing.T) {
	stub := &stubSolver{solveErr: errors.New("simulated solve failure")}
	c := NewCache(stub, 5*time.Minute)
	target, _ := url.Parse("https://example.com/")

	_, err := c.LookupOrSolve(context.Background(), target, "1.2.3.4")
	if err == nil {
		t.Fatalf("expected solve error")
	}
	if c.Size() != 0 {
		t.Errorf("failed solve should not populate cache, Size=%d", c.Size())
	}
	// Second attempt should call the solver again.
	_, _ = c.LookupOrSolve(context.Background(), target, "1.2.3.4")
	if got := stub.calls.Load(); got != 2 {
		t.Errorf("solver called %d times, want 2 (no cache on error)", got)
	}
}

// --- disk persistence ---

func TestCacheSaveAndLoad(t *testing.T) {
	stub := &stubSolver{
		cookies: []*http.Cookie{
			{Name: "cf_clearance", Value: "abc123"},
			{Name: "__cf_bm", Value: "bm456"},
		},
	}
	c := NewCache(stub, 1*time.Hour)
	target, _ := url.Parse("https://example.com/")

	// Solve and cache an entry.
	_, err := c.LookupOrSolve(context.Background(), target, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if c.Size() != 1 {
		t.Fatalf("expected 1 entry, got %d", c.Size())
	}

	// Save to temp file.
	tmpDir := t.TempDir()
	if err := c.SaveToDir(tmpDir); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Load into a fresh cache.
	c2 := NewCache(stub, 1*time.Hour)
	loaded, err := c2.LoadFromDir(tmpDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded != 1 {
		t.Errorf("loaded %d entries, want 1", loaded)
	}

	// Verify the loaded entry is usable.
	sol := c2.Lookup("example.com", "1.2.3.4")
	if sol == nil {
		t.Fatal("loaded entry not found via Lookup")
	}
	if sol.Cookie("cf_clearance") != "abc123" {
		t.Errorf("cf_clearance = %q, want abc123", sol.Cookie("cf_clearance"))
	}
}

func TestCacheDirLayout(t *testing.T) {
	stub := &stubSolver{
		cookies: []*http.Cookie{{Name: "cf_clearance", Value: "v1"}},
	}
	c := NewCache(stub, 1*time.Hour)
	target1, _ := url.Parse("https://www.k-ruoka.fi/")
	target2, _ := url.Parse("https://example.com/")

	_, _ = c.LookupOrSolve(context.Background(), target1, "1.2.3.4")
	_, _ = c.LookupOrSolve(context.Background(), target2, "5.6.7.8")

	dir := t.TempDir()
	if err := c.SaveToDir(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Verify hostname-partitioned directory layout:
	//   {dir}/www.k-ruoka.fi/1.2.3.4.json
	//   {dir}/example.com/5.6.7.8.json
	for _, want := range []string{
		"www.k-ruoka.fi/1.2.3.4.json",
		"example.com/5.6.7.8.json",
	} {
		full := dir + "/" + want
		if _, err := os.Stat(full); err != nil {
			t.Errorf("expected file %s, got error: %v", want, err)
		}
	}

	// Verify round-trip load.
	c2 := NewCache(stub, 1*time.Hour)
	loaded, err := c2.LoadFromDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded != 2 {
		t.Errorf("loaded %d, want 2", loaded)
	}
}

func TestCacheLoadSkipsExpired(t *testing.T) {
	stub := &stubSolver{
		cookies: []*http.Cookie{{Name: "cf_clearance", Value: "old"}},
	}
	c := NewCache(stub, 1*time.Millisecond)

	now := time.Unix(1_000_000, 0)
	c.nowFn = func() time.Time { return now }

	target, _ := url.Parse("https://example.com/")
	_, _ = c.LookupOrSolve(context.Background(), target, "1.2.3.4")

	tmpDir := t.TempDir()
	_ = c.SaveToDir(tmpDir)

	// Advance clock past expiry.
	c2 := NewCache(stub, 1*time.Millisecond)
	c2.nowFn = func() time.Time { return now.Add(1 * time.Hour) }
	loaded, _ := c2.LoadFromDir(tmpDir)
	if loaded != 0 {
		t.Errorf("expired entries should not be loaded, got %d", loaded)
	}
}

func TestCookiesPreservedAcrossRotation(t *testing.T) {
	// Simulate: solve on IP A, rotate to IP B, check IP A's cookies
	// are still in the cache.
	stub := &stubSolver{
		cookies: []*http.Cookie{{Name: "cf_clearance", Value: "preserved"}},
	}
	c := NewCache(stub, 1*time.Hour)
	target, _ := url.Parse("https://example.com/")

	_, _ = c.LookupOrSolve(context.Background(), target, "1.2.3.4")
	if c.Size() != 1 {
		t.Fatal("expected 1 cached entry")
	}

	// Simulate rotation: DO NOT call InvalidateExit (new behavior).
	// Old code would call c.InvalidateExit("1.2.3.4") here.
	// Now we just snapshot the new IP and move on.

	// Verify cookies are still accessible for the old IP.
	sol := c.Lookup("example.com", "1.2.3.4")
	if sol == nil {
		t.Fatal("cookies should survive rotation")
	}
	if sol.Cookie("cf_clearance") != "preserved" {
		t.Errorf("cf_clearance = %q, want preserved", sol.Cookie("cf_clearance"))
	}

	// A lookup for the NEW IP should miss (no cookies solved yet).
	if c.Lookup("example.com", "5.6.7.8") != nil {
		t.Error("new IP should not have cached cookies")
	}
}

// --- circuit breaker ---

func TestCircuitBreakerClosedInitially(t *testing.T) {
	c := NewCache(&stubSolver{}, 5*time.Minute)
	if c.CircuitOpen("example.com", "1.2.3.4") {
		t.Error("fresh cache should have closed circuit for all hosts")
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	c := NewCache(&stubSolver{}, 5*time.Minute)
	c.SetCircuitBreakerTuning(3, 10*time.Minute)

	// First two failures don't open.
	if opened := c.MarkRetryFailed("bad.host", "1.2.3.4"); opened {
		t.Error("failure 1 should not open circuit")
	}
	if c.CircuitOpen("bad.host", "1.2.3.4") {
		t.Error("circuit should still be closed after 1 failure")
	}
	if opened := c.MarkRetryFailed("bad.host", "1.2.3.4"); opened {
		t.Error("failure 2 should not open circuit")
	}
	if c.CircuitOpen("bad.host", "1.2.3.4") {
		t.Error("circuit should still be closed after 2 failures")
	}
	// Third failure opens.
	if opened := c.MarkRetryFailed("bad.host", "1.2.3.4"); !opened {
		t.Error("failure 3 should open circuit")
	}
	if !c.CircuitOpen("bad.host", "1.2.3.4") {
		t.Error("circuit should be open after 3 failures")
	}
}

func TestCircuitBreakerIsolatesHosts(t *testing.T) {
	c := NewCache(&stubSolver{}, 5*time.Minute)
	c.SetCircuitBreakerTuning(2, 10*time.Minute)

	c.MarkRetryFailed("bad.host", "1.2.3.4")
	c.MarkRetryFailed("bad.host", "1.2.3.4")
	if !c.CircuitOpen("bad.host", "1.2.3.4") {
		t.Error("bad.host should be open")
	}
	if c.CircuitOpen("good.host", "1.2.3.4") {
		t.Error("good.host should not be affected by bad.host's circuit")
	}
}

func TestCircuitBreakerIsolatesExitIPs(t *testing.T) {
	c := NewCache(&stubSolver{}, 5*time.Minute)
	c.SetCircuitBreakerTuning(2, 10*time.Minute)

	// Host fails on IP A but hasn't been tried on IP B.
	c.MarkRetryFailed("mixed.host", "1.1.1.1")
	c.MarkRetryFailed("mixed.host", "1.1.1.1")
	if !c.CircuitOpen("mixed.host", "1.1.1.1") {
		t.Error("mixed.host on 1.1.1.1 should be open")
	}
	// Same host on a different IP should NOT be circuit-opened.
	if c.CircuitOpen("mixed.host", "2.2.2.2") {
		t.Error("mixed.host on 2.2.2.2 should NOT be blocked — different exit IP")
	}
}

func TestCircuitBreakerSuccessResets(t *testing.T) {
	c := NewCache(&stubSolver{}, 5*time.Minute)
	c.SetCircuitBreakerTuning(3, 10*time.Minute)

	c.MarkRetryFailed("flaky.host", "1.2.3.4")
	c.MarkRetryFailed("flaky.host", "1.2.3.4")
	// One away from opening.
	c.MarkRetrySucceeded("flaky.host", "1.2.3.4")
	// Now three more failures should be needed to open again.
	c.MarkRetryFailed("flaky.host", "1.2.3.4")
	c.MarkRetryFailed("flaky.host", "1.2.3.4")
	if c.CircuitOpen("flaky.host", "1.2.3.4") {
		t.Error("circuit should NOT be open after success reset + 2 new failures")
	}
	if opened := c.MarkRetryFailed("flaky.host", "1.2.3.4"); !opened {
		t.Error("third new failure after reset should open circuit")
	}
}

func TestCircuitBreakerAutoCloses(t *testing.T) {
	c := NewCache(&stubSolver{}, 5*time.Minute)
	c.SetCircuitBreakerTuning(2, 10*time.Minute)

	// Inject fake clock.
	now := time.Unix(1_000_000, 0)
	c.nowFn = func() time.Time { return now }

	c.MarkRetryFailed("pinned.host", "1.2.3.4")
	c.MarkRetryFailed("pinned.host", "1.2.3.4")
	if !c.CircuitOpen("pinned.host", "1.2.3.4") {
		t.Fatal("expected circuit open")
	}

	// Advance clock past open duration.
	now = now.Add(11 * time.Minute)
	if c.CircuitOpen("pinned.host", "1.2.3.4") {
		t.Error("circuit should auto-close after open duration elapses")
	}

	// The auto-close also resets the counter — one failure alone
	// should not re-open.
	c.MarkRetryFailed("pinned.host", "1.2.3.4")
	if c.CircuitOpen("pinned.host", "1.2.3.4") {
		t.Error("circuit should not reopen on first failure after auto-close")
	}
}

func TestCircuitBreakerStatus(t *testing.T) {
	c := NewCache(&stubSolver{}, 5*time.Minute)
	c.SetCircuitBreakerTuning(2, 10*time.Minute)

	c.MarkRetryFailed("bad.host", "1.2.3.4")
	c.MarkRetryFailed("bad.host", "1.2.3.4")
	c.MarkRetryFailed("flaky.host", "1.2.3.4")

	status := c.CircuitStatus()
	if len(status) != 2 {
		t.Errorf("status has %d entries, want 2", len(status))
	}
	// Keys are now "host|exitIP"
	badKey := "bad.host|1.2.3.4"
	flakyKey := "flaky.host|1.2.3.4"
	if !status[badKey].Open {
		t.Errorf("%s should be Open=true", badKey)
	}
	if status[badKey].ConsecutiveFailures != 2 {
		t.Errorf("%s failures = %d, want 2", badKey, status[badKey].ConsecutiveFailures)
	}
	if status[flakyKey].Open {
		t.Errorf("%s should be Open=false", flakyKey)
	}
	if status[flakyKey].ConsecutiveFailures != 1 {
		t.Errorf("%s failures = %d, want 1", flakyKey, status[flakyKey].ConsecutiveFailures)
	}
}
