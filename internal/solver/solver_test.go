package solver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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
