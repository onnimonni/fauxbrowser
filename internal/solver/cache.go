package solver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Cache wraps a Solver with a TTL-bound cache keyed on
// (host, exit_ip). CF clearance cookies are preserved across VPN
// IP rotations — they're only invalidated when Cloudflare
// explicitly rejects them (CF-specific 403). On a 429 rotation
// the cookies stay cached so they're ready if we cycle back to
// the same exit IP later.
//
// Concurrent solves for the same key are deduplicated via
// golang.org/x/sync/singleflight: 100 simultaneous requests to a
// challenged host trigger ONE Chromium launch, not 100.
//
// Per-host circuit breaker: when the transport reports that a
// solver-extracted cookie stamping did NOT satisfy the WAF on
// retry (MarkRetryFailed), the failure is recorded per host. After
// N consecutive failures, the circuit opens and CircuitOpen(host)
// returns true for OpenDuration. While open, the transport skips
// the solver entirely and returns the challenge response to the
// caller as-is — no point spending seconds launching chromium for
// a host whose WAF cookie-pins to the solving browser's TLS
// fingerprint (we'd just loop forever on the current retry
// semantics). This is the host-agnostic generalization of the
// cf-clearance-cross-fingerprint-pinning pattern.
//
// Any solve whose retry CLEARS the challenge calls
// MarkRetrySucceeded(host) and resets the counter.
type Cache struct {
	solver Solver
	ttl    time.Duration

	// Circuit breaker tuning. Defaults applied in NewCache.
	cbThreshold int           // consecutive MarkRetryFailed to open the circuit
	cbOpenFor   time.Duration // how long the circuit stays open after threshold

	// storeDir is the directory for per-entry cookie persistence.
	// Empty = no disk persistence.
	storeDir string

	mu       sync.RWMutex
	entries  map[string]*cacheEntry
	circuits map[string]*circuitState // keyed by host

	sf singleflight.Group

	// nowFn is injectable for tests.
	nowFn func() time.Time
}

// circuitState tracks per-host retry-failure state for the circuit
// breaker. Protected by Cache.mu.
type circuitState struct {
	consecutiveFailures int
	openedUntil         time.Time // zero = not open
}

type cacheEntry struct {
	solution *Solution
	expiry   time.Time
	exitIP   string // for InvalidateExit
}

// NewCache wraps solver with a TTL cache. ttl <= 0 disables
// expiry (entries live until InvalidateExit / Invalidate).
//
// The circuit breaker defaults to 3 consecutive retry-failures
// opening the circuit for 10 minutes. Override via
// SetCircuitBreakerTuning after construction.
func NewCache(solver Solver, ttl time.Duration) *Cache {
	return &Cache{
		solver:      solver,
		ttl:         ttl,
		cbThreshold: 3,
		cbOpenFor:   10 * time.Minute,
		entries:     make(map[string]*cacheEntry),
		circuits:    make(map[string]*circuitState),
		nowFn:       time.Now,
	}
}

// SetStoreDir sets the directory for per-entry cookie persistence.
// When set, every successful solve auto-persists the entry to disk,
// and every invalidation deletes the file.
func (c *Cache) SetStoreDir(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeDir = dir
}

// SetCircuitBreakerTuning overrides the default threshold and
// open-duration. threshold <= 0 or openFor <= 0 restores the
// default for that field. Safe to call at any time; does not
// affect currently-open circuits.
func (c *Cache) SetCircuitBreakerTuning(threshold int, openFor time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if threshold > 0 {
		c.cbThreshold = threshold
	}
	if openFor > 0 {
		c.cbOpenFor = openFor
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
	sol.hostHint = host // for disk persistence reconstruction
	c.mu.Lock()
	storeDir := c.storeDir
	expiry := time.Time{}
	if c.ttl > 0 {
		expiry = c.nowFn().Add(c.ttl)
	}
	c.entries[cacheKey(host, exitIP)] = &cacheEntry{
		solution: sol,
		expiry:   expiry,
		exitIP:   exitIP,
	}
	c.mu.Unlock()

	// Auto-persist to disk outside the lock.
	if storeDir != "" {
		if err := c.SaveEntry(storeDir, host, exitIP); err != nil {
			slog.Warn("solver: auto-persist failed", "host", host, "err", err)
		}
	}
}

// Invalidate drops the cached entry for (host, exitIP). Called by
// the transport when a stamped retry STILL got a challenge — the
// cookie was stale.
func (c *Cache) Invalidate(host, exitIP string) {
	c.mu.Lock()
	storeDir := c.storeDir
	delete(c.entries, cacheKey(host, exitIP))
	c.mu.Unlock()

	if storeDir != "" {
		c.DeleteEntry(storeDir, host, exitIP)
	}
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
// and /.internal/healthz).
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Solver returns the underlying solver, mostly for /.internal/healthz to
// expose its name.
func (c *Cache) Solver() Solver { return c.solver }

// CircuitOpen reports whether the solver circuit for host is
// currently open. When open, the transport should skip invoking
// the solver on challenge responses for this host and return the
// challenge response directly to the caller.
//
// The circuit auto-closes after cbOpenFor elapses since it was
// opened; the next call after that returns false and the transport
// is free to try solving again.
func (c *Cache) CircuitOpen(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.circuits[host]
	if !ok {
		return false
	}
	if st.openedUntil.IsZero() {
		return false
	}
	if c.nowFn().After(st.openedUntil) {
		// Auto-close. Reset counters too — next failure starts
		// over from 1. This gives the host a fresh chance to
		// prove it's solvable post-rotation or post-WAF-config-
		// change.
		st.openedUntil = time.Time{}
		st.consecutiveFailures = 0
		return false
	}
	return true
}

// MarkRetryFailed records that a stamped-cookie retry for host
// STILL came back as a challenge. After cbThreshold consecutive
// failures the circuit opens for cbOpenFor.
//
// Returns true if this call transitioned the circuit from closed
// to open (for logging).
func (c *Cache) MarkRetryFailed(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.circuits[host]
	if !ok {
		st = &circuitState{}
		c.circuits[host] = st
	}
	st.consecutiveFailures++
	if st.consecutiveFailures >= c.cbThreshold && st.openedUntil.IsZero() {
		st.openedUntil = c.nowFn().Add(c.cbOpenFor)
		return true
	}
	return false
}

// MarkRetrySucceeded records that a stamped-cookie retry for host
// cleared the challenge. Resets the consecutive-failure counter
// and closes any open circuit. Safe to call on every successful
// solve.
func (c *Cache) MarkRetrySucceeded(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st, ok := c.circuits[host]; ok {
		st.consecutiveFailures = 0
		st.openedUntil = time.Time{}
	}
}

// CircuitStatus returns a read-only snapshot of the per-host
// circuit state for /.internal/healthz or debugging. Keys are host names.
func (c *Cache) CircuitStatus() map[string]CircuitStatusEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]CircuitStatusEntry, len(c.circuits))
	now := c.nowFn()
	for host, st := range c.circuits {
		open := !st.openedUntil.IsZero() && now.Before(st.openedUntil)
		var remaining time.Duration
		if open {
			remaining = st.openedUntil.Sub(now)
		}
		out[host] = CircuitStatusEntry{
			ConsecutiveFailures: st.consecutiveFailures,
			Open:                open,
			OpenFor:             remaining,
		}
	}
	return out
}

// CircuitStatusEntry is the public view of a single host's circuit
// state.
type CircuitStatusEntry struct {
	ConsecutiveFailures int
	Open                bool
	OpenFor             time.Duration
}

// --- disk persistence (directory-based, one file per entry) ---
//
// Each (host, exitIP) pair is stored as a separate JSON file in a
// directory. Filenames are "{host}@{exitIP}.json" — both hostname
// and IPv4 are filename-safe, and "@" is not valid in either.
//
// Benefits over a single JSON blob:
//   - O(1) per-entry writes: only the changed entry is rewritten.
//   - Crash-safe: a crash mid-write corrupts at most one entry.
//   - Inspectable: `ls /var/lib/fauxbrowser/cookies/` lists all
//     cached sessions; `cat` any file to see the cookies.
//   - Filesystem IS the index: no need to parse a large file on
//     startup to find one entry.

// persistEntry is the JSON-serializable form of a cacheEntry.
type persistEntry struct {
	Host     string         `json:"host"`
	ExitIP   string         `json:"exit_ip"`
	Cookies  []*http.Cookie `json:"cookies"`
	UA       string         `json:"user_agent"`
	SolvedAt time.Time      `json:"solved_at"`
	Expiry   time.Time      `json:"expiry"`
}

// entryFilename returns the filename for a (host, exitIP) pair.
func entryFilename(host, exitIP string) string {
	return host + "@" + exitIP + ".json"
}

// SaveEntry persists a single cache entry to disk. Called after
// every successful solve. Atomic via temp-file + rename.
func (c *Cache) SaveEntry(dir, host, exitIP string) error {
	c.mu.RLock()
	e, ok := c.entries[cacheKey(host, exitIP)]
	if !ok {
		c.mu.RUnlock()
		return nil // nothing to save
	}
	pe := persistEntry{
		Host:     host,
		ExitIP:   exitIP,
		Cookies:  e.solution.Cookies,
		UA:       e.solution.UserAgent,
		SolvedAt: e.solution.SolvedAt,
		Expiry:   e.expiry,
	}
	c.mu.RUnlock()

	data, err := json.MarshalIndent(pe, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, entryFilename(host, exitIP)+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, entryFilename(host, exitIP)))
}

// DeleteEntry removes a single cache entry from disk. Called on
// CF-specific 403 invalidation.
func (c *Cache) DeleteEntry(dir, host, exitIP string) {
	path := filepath.Join(dir, entryFilename(host, exitIP))
	_ = os.Remove(path)
}

// SaveToDir persists all unexpired cache entries to a directory.
// Each entry is written as a separate JSON file. Useful for
// periodic full sync or clean shutdown.
func (c *Cache) SaveToDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	c.mu.RLock()
	now := c.nowFn()
	var toSave []persistEntry
	for _, e := range c.entries {
		if c.ttl > 0 && now.After(e.expiry) {
			continue
		}
		toSave = append(toSave, persistEntry{
			Host:     e.solution.hostHint,
			ExitIP:   e.exitIP,
			Cookies:  e.solution.Cookies,
			UA:       e.solution.UserAgent,
			SolvedAt: e.solution.SolvedAt,
			Expiry:   e.expiry,
		})
	}
	c.mu.RUnlock()

	for _, pe := range toSave {
		data, err := json.MarshalIndent(pe, "", "  ")
		if err != nil {
			return err
		}
		tmp := filepath.Join(dir, entryFilename(pe.Host, pe.ExitIP)+".tmp")
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, entryFilename(pe.Host, pe.ExitIP))); err != nil {
			return err
		}
	}
	return nil
}

// LoadFromDir restores cache entries from a directory previously
// written by SaveToDir or SaveEntry. Expired entries are skipped
// and their files are deleted. Entries that conflict with existing
// in-memory entries are skipped (in-memory wins). Returns the
// number of entries loaded.
func (c *Cache) LoadFromDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowFn()
	loaded, expired := 0, 0
	for _, de := range entries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			continue
		}
		var pe persistEntry
		if err := json.Unmarshal(data, &pe); err != nil {
			continue
		}
		if c.ttl > 0 && now.After(pe.Expiry) {
			// Clean up expired files from disk.
			_ = os.Remove(filepath.Join(dir, de.Name()))
			expired++
			continue
		}
		key := cacheKey(pe.Host, pe.ExitIP)
		if _, exists := c.entries[key]; exists {
			continue
		}
		c.entries[key] = &cacheEntry{
			solution: &Solution{
				Cookies:   pe.Cookies,
				UserAgent: pe.UA,
				SolvedAt:  pe.SolvedAt,
				hostHint:  pe.Host,
			},
			expiry: pe.Expiry,
			exitIP: pe.ExitIP,
		}
		loaded++
	}
	slog.Info("solver: loaded cookie cache from disk",
		"dir", dir, "loaded", loaded, "expired_cleaned", expired)
	return loaded, nil
}

// Backward-compat aliases for callers that haven't migrated yet.

// SaveToFile is a backward-compatible alias for SaveToDir.
// If path ends in ".json", it uses the parent directory.
func (c *Cache) SaveToFile(path string) error {
	dir := path
	if filepath.Ext(path) == ".json" {
		dir = filepath.Dir(path)
	}
	return c.SaveToDir(dir)
}

// LoadFromFile is a backward-compatible alias for LoadFromDir.
// If path ends in ".json", it uses the parent directory.
func (c *Cache) LoadFromFile(path string) (int, error) {
	dir := path
	if filepath.Ext(path) == ".json" {
		dir = filepath.Dir(path)
	}
	return c.LoadFromDir(dir)
}
