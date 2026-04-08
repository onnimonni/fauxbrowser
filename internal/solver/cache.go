package solver

import (
	"context"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Cache wraps a Solver with a TTL-bound cache keyed on
// (host, exit_ip). When the rotator swaps to a new exit IP, the
// transport calls InvalidateExit(ip) to drop every entry bound to
// that IP — clearance cookies are exit-IP-bound and meaningless
// after rotation.
//
// Concurrent solves for the same key are deduplicated via
// golang.org/x/sync/singleflight: 100 simultaneous requests to a
// challenged host trigger ONE Chromium launch, not 100.
type Cache struct {
	solver Solver
	ttl    time.Duration

	mu      sync.RWMutex
	entries map[string]*cacheEntry

	sf singleflight.Group

	// nowFn is injectable for tests.
	nowFn func() time.Time
}

type cacheEntry struct {
	solution *Solution
	expiry   time.Time
	exitIP   string // for InvalidateExit
}

// NewCache wraps solver with a TTL cache. ttl <= 0 disables
// expiry (entries live until InvalidateExit / Invalidate).
func NewCache(solver Solver, ttl time.Duration) *Cache {
	return &Cache{
		solver:  solver,
		ttl:     ttl,
		entries: make(map[string]*cacheEntry),
		nowFn:   time.Now,
	}
}

// cacheKey is the lookup key for the entries map.
func cacheKey(host, exitIP string) string {
	return host + "|" + exitIP
}

// Lookup returns a cached Solution for (host, exitIP) if it
// exists and hasn't expired.
func (c *Cache) Lookup(host, exitIP string) *Solution {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[cacheKey(host, exitIP)]
	if !ok {
		return nil
	}
	if c.ttl > 0 && c.nowFn().After(e.expiry) {
		return nil
	}
	return e.solution
}

// LookupOrSolve returns the cached solution for (host, exitIP) or,
// if absent/expired, invokes the solver. Concurrent callers for
// the same key block on a single solve via singleflight.
func (c *Cache) LookupOrSolve(ctx context.Context, target *url.URL, exitIP string) (*Solution, error) {
	if hit := c.Lookup(target.Host, exitIP); hit != nil {
		return hit, nil
	}

	// Singleflight: dedupe concurrent solves for the same key.
	key := cacheKey(target.Host, exitIP)
	v, err, _ := c.sf.Do(key, func() (any, error) {
		// Re-check cache inside the singleflight callback in case
		// another goroutine just finished a solve.
		if hit := c.Lookup(target.Host, exitIP); hit != nil {
			return hit, nil
		}
		sol, err := c.solver.Solve(ctx, target)
		if err != nil {
			return nil, err
		}
		c.store(target.Host, exitIP, sol)
		return sol, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Solution), nil
}

func (c *Cache) store(host, exitIP string, sol *Solution) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expiry := time.Time{}
	if c.ttl > 0 {
		expiry = c.nowFn().Add(c.ttl)
	}
	c.entries[cacheKey(host, exitIP)] = &cacheEntry{
		solution: sol,
		expiry:   expiry,
		exitIP:   exitIP,
	}
}

// Invalidate drops the cached entry for (host, exitIP). Called by
// the transport when a stamped retry STILL got a challenge — the
// cookie was stale.
func (c *Cache) Invalidate(host, exitIP string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, cacheKey(host, exitIP))
}

// InvalidateExit drops every entry bound to a given exit IP. The
// rotator calls this on every successful peer swap because
// clearance cookies are bound to the (UA, IP) tuple and are
// meaningless once the IP changes.
func (c *Cache) InvalidateExit(exitIP string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	dropped := 0
	for k, e := range c.entries {
		if e.exitIP == exitIP {
			delete(c.entries, k)
			dropped++
		}
	}
	return dropped
}

// Size returns the number of cached entries (mostly for tests
// and /healthz).
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Solver returns the underlying solver, mostly for /healthz to
// expose its name.
func (c *Cache) Solver() Solver { return c.solver }
