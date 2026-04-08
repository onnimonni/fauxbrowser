package solver

import (
	"context"
	"log/slog"
	nurl "net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Cache memoises solver results per (session, registrable domain). A nil
// Solver turns this into a no-op cache and LookupOrSolve is the identity.
type Cache struct {
	solver Solver
	ttl    time.Duration

	mu sync.Mutex
	m  map[cacheKey]*Result

	sf singleflight.Group
}

type cacheKey struct {
	session string
	domain  string
}

func NewCache(s Solver, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 25 * time.Minute
	}
	return &Cache{
		solver: s,
		ttl:    ttl,
		m:      make(map[cacheKey]*Result),
	}
}

// Solver returns the underlying Solver (may be nil).
func (c *Cache) Solver() Solver { return c.solver }

// LookupOrSolve returns a valid Result, blocking concurrent callers for the
// same (session, domain) on a single Solve. Callers that hit an existing
// valid entry bypass Solve entirely. The upstreamProxy is forwarded to the
// solver so it egresses via the same IP as the fast path.
func (c *Cache) LookupOrSolve(ctx context.Context, session string, target *nurl.URL, upstreamProxy string) (*Result, error) {
	if c.solver == nil {
		return nil, nil
	}
	key := cacheKey{session: session, domain: registrableDomain(target.Host)}

	if r := c.peek(key); r != nil {
		return r, nil
	}

	sfKey := key.session + "|" + key.domain
	v, err, _ := c.sf.Do(sfKey, func() (any, error) {
		// Re-check under singleflight in case another caller populated.
		if r := c.peek(key); r != nil {
			return r, nil
		}

		slog.Info("solver invoke", "solver", c.solver.Name(),
			"domain", key.domain, "session", session)
		r, err := c.solver.Solve(ctx, target, upstreamProxy)
		if err != nil {
			return nil, err
		}
		if r.ExpiresAt.IsZero() {
			r.ExpiresAt = time.Now().Add(c.ttl)
		}
		c.mu.Lock()
		c.m[key] = r
		c.mu.Unlock()
		slog.Info("solver success", "solver", c.solver.Name(),
			"domain", key.domain, "cookies", len(r.Cookies),
			"expires_in", time.Until(r.ExpiresAt).Round(time.Second))
		return r, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Result), nil
}

// Peek returns a cached, still-valid Result for (session, host) without
// triggering a solve. Returns nil on miss or stale entry. Used by the
// transport to proactively stamp cookies before the first upstream hit.
func (c *Cache) Peek(session string, host string) *Result {
	return c.peek(cacheKey{session: session, domain: registrableDomain(host)})
}

func (c *Cache) peek(key cacheKey) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.m[key]; ok && time.Now().Before(r.ExpiresAt) {
		return r
	}
	return nil
}

// Invalidate drops any cached solve for (session, domain). Call this when a
// re-fetch using the cached cookies comes back looking like a challenge
// again, so the next request triggers a fresh solve.
func (c *Cache) Invalidate(session string, host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, cacheKey{session: session, domain: registrableDomain(host)})
}

// registrableDomain is a cheap second-level-domain extractor that is good
// enough for our cache key. It does NOT consult the public suffix list —
// for our purposes, grouping under "foo.co.uk" vs "example.co.uk" is a
// minor over-aggression that only causes extra solves, never wrong ones.
func registrableDomain(hostport string) string {
	h := hostport
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimPrefix(strings.ToLower(h), "www.")
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
