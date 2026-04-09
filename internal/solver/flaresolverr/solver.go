package flaresolverr

import (
	"context"
	"net/http"
	nurl "net/url"
	"time"

	"github.com/onnimonni/fauxbrowser/internal/solver"
)

// Solver adapts a FlareSolverr Client to the solver.Solver interface.
type Solver struct {
	Client *Client
	// MaxTimeoutMillis caps how long FlareSolverr spends on a single solve.
	MaxTimeoutMillis int
}

// New returns a Solver ready to use.
func New(baseURL string) *Solver {
	return &Solver{
		Client:           NewClient(baseURL),
		MaxTimeoutMillis: 90000,
	}
}

// ensure we satisfy solver.Solver
var _ solver.Solver = (*Solver)(nil)

func (s *Solver) Name() string { return "flaresolverr" }

func (s *Solver) Solve(ctx context.Context, target *nurl.URL, upstreamProxy string) (*solver.Result, error) {
	resp, err := s.Client.Get(ctx, target.String(), upstreamProxy, s.MaxTimeoutMillis)
	if err != nil {
		return nil, err
	}
	sol := resp.Solution
	cookies := make([]*http.Cookie, 0, len(sol.Cookies))
	for _, c := range sol.Cookies {
		httpCookie := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		}
		if c.Expires > 0 {
			httpCookie.Expires = time.Unix(int64(c.Expires), 0)
		}
		cookies = append(cookies, httpCookie)
	}
	now := time.Now()
	// Conservative: use the earliest cookie expiry, capped at 25 min, so we
	// re-solve before CF starts rejecting.
	expires := now.Add(25 * time.Minute)
	for _, c := range cookies {
		if !c.Expires.IsZero() && c.Expires.Before(expires) && c.Expires.After(now) {
			expires = c.Expires
		}
	}
	return &solver.Result{
		Cookies:   cookies,
		UserAgent: sol.UserAgent,
		SolvedAt:  now,
		ExpiresAt: expires,
	}, nil
}
