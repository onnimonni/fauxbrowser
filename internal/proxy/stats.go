package proxy

import (
	"sort"
	"sync"
	"time"
)

// Diagnosis is the computed assessment of a host's reachability
// through fauxbrowser's current exit network.
type Diagnosis string

const (
	DiagnosisHealthy          Diagnosis = "healthy"
	DiagnosisSolverHandlesIt  Diagnosis = "solver_handles_it"
	DiagnosisCookieBinding    Diagnosis = "cookie_binding"
	DiagnosisIPReputationBlock Diagnosis = "ip_reputation_block"
	DiagnosisRateLimited      Diagnosis = "rate_limited"
	DiagnosisIPDependent      Diagnosis = "ip_dependent"
	DiagnosisTooFewData       Diagnosis = "too_few_data"
)

// StatsTracker records per-host request outcomes for diagnostics.
// All methods are goroutine-safe.
type StatsTracker struct {
	mu    sync.RWMutex
	hosts map[string]*HostStats
	nowFn func() time.Time
}

// HostStats aggregates request outcomes for a single hostname.
type HostStats struct {
	Host      string    `json:"host"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	TotalRequests   int64 `json:"total_requests"`
	Successes       int64 `json:"successes"`
	ChallengesSeen  int64 `json:"challenges_seen"`
	SolverInvoked   int64 `json:"solver_invoked"`
	SolverSucceeded int64 `json:"solver_succeeded"`
	SolverFailed    int64 `json:"solver_failed"`
	SolverErrors    int64 `json:"solver_errors"`
	CircuitOpened   int64 `json:"circuit_opened"`
	RateLimited     int64 `json:"rate_limited"`
	Rotations       int64 `json:"rotations"`

	ExitIPs map[string]*ExitIPStats `json:"exit_ips"`
}

// ExitIPStats tracks per-exit-IP outcomes for one host.
type ExitIPStats struct {
	Requests   int64     `json:"requests"`
	Successes  int64     `json:"successes"`
	Challenges int64     `json:"challenges"`
	LastStatus int       `json:"last_status"`
	LastSeen   time.Time `json:"last_seen"`
}

// HostSummary is the JSON-serializable view for the admin API.
type HostSummary struct {
	HostStats
	ExitIPsTried     int       `json:"exit_ips_tried"`
	ExitIPsSucceeded int       `json:"exit_ips_succeeded"`
	Diagnosis        Diagnosis `json:"diagnosis"`
	Recommendation   string    `json:"recommendation"`
}

func NewStatsTracker() *StatsTracker {
	return &StatsTracker{
		hosts: make(map[string]*HostStats),
		nowFn: time.Now,
	}
}

func (t *StatsTracker) getOrCreate(host string) *HostStats {
	s, ok := t.hosts[host]
	if !ok {
		now := t.nowFn()
		s = &HostStats{
			Host:      host,
			FirstSeen: now,
			ExitIPs:   make(map[string]*ExitIPStats),
		}
		t.hosts[host] = s
	}
	s.LastSeen = t.nowFn()
	return s
}

func (t *StatsTracker) getOrCreateIP(s *HostStats, exitIP string) *ExitIPStats {
	ip, ok := s.ExitIPs[exitIP]
	if !ok {
		ip = &ExitIPStats{}
		s.ExitIPs[exitIP] = ip
	}
	ip.LastSeen = t.nowFn()
	return ip
}

// --- Recording methods (called from transport.RoundTrip) ---

func (t *StatsTracker) RecordRequest(host, exitIP string, status int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.getOrCreate(host)
	s.TotalRequests++
	ip := t.getOrCreateIP(s, exitIP)
	ip.Requests++
	ip.LastStatus = status
	if status >= 200 && status < 400 {
		s.Successes++
		ip.Successes++
	}
	if status == 429 {
		s.RateLimited++
	}
}

func (t *StatsTracker) RecordChallenge(host, exitIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.getOrCreate(host)
	s.ChallengesSeen++
	ip := t.getOrCreateIP(s, exitIP)
	ip.Challenges++
}

func (t *StatsTracker) RecordSolverInvoked(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.getOrCreate(host).SolverInvoked++
}

func (t *StatsTracker) RecordSolverSuccess(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.getOrCreate(host).SolverSucceeded++
}

func (t *StatsTracker) RecordSolverFailed(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.getOrCreate(host).SolverFailed++
}

func (t *StatsTracker) RecordSolverError(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.getOrCreate(host).SolverErrors++
}

func (t *StatsTracker) RecordCircuitOpened(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.getOrCreate(host).CircuitOpened++
}

func (t *StatsTracker) RecordRotation(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.getOrCreate(host).Rotations++
}

// --- Query methods (called from admin API) ---

// Diagnose computes a diagnosis + recommendation for a host.
func (t *StatsTracker) Diagnose(host string) (Diagnosis, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.hosts[host]
	if !ok {
		return DiagnosisTooFewData, "no data for this host"
	}
	return diagnose(s)
}

func diagnose(s *HostStats) (Diagnosis, string) {
	if s.TotalRequests < 3 {
		return DiagnosisTooFewData, "fewer than 3 requests — not enough data"
	}

	successRate := float64(s.Successes) / float64(s.TotalRequests)
	ipsWithSuccess := 0
	ipsTotal := len(s.ExitIPs)
	for _, ip := range s.ExitIPs {
		if ip.Successes > 0 {
			ipsWithSuccess++
		}
	}

	// Healthy: >90% success rate
	if successRate > 0.9 {
		return DiagnosisHealthy, "no action needed"
	}

	// Rate limited: >30% 429s
	if s.TotalRequests > 0 && float64(s.RateLimited)/float64(s.TotalRequests) > 0.3 {
		return DiagnosisRateLimited, "slow down request rate or add more rotation delay"
	}

	// Solver handles it: challenges seen but solver resolves them
	if s.ChallengesSeen > 0 && s.SolverSucceeded > 0 && s.SolverFailed == 0 {
		return DiagnosisSolverHandlesIt, "solver working — consider increasing solver TTL"
	}

	// Cookie binding: solver extracts cookies but they don't satisfy the WAF
	if s.SolverFailed > 0 && ipsTotal >= 3 && ipsWithSuccess == 0 {
		return DiagnosisCookieBinding, "cookies don't port from solver to fast path — needs browser passthrough mode or residential proxy"
	}

	// IP reputation block: challenges on all requests, all IPs fail
	if s.ChallengesSeen == s.TotalRequests && ipsTotal >= 3 && ipsWithSuccess == 0 {
		return DiagnosisIPReputationBlock, "all exit IPs blocked — needs residential proxy or paid VPN tier"
	}

	// IP dependent: some IPs work, others don't
	if ipsWithSuccess > 0 && ipsWithSuccess < ipsTotal {
		return DiagnosisIPDependent, "some exit IPs work, some don't — rotate until a good one sticks"
	}

	// Cookie binding: solver failures across multiple IPs
	if s.SolverFailed > 0 && ipsTotal >= 2 {
		return DiagnosisCookieBinding, "cookies don't port from solver to fast path — needs browser passthrough mode or residential proxy"
	}

	// Fallback: IP reputation if all challenges, no successes
	if s.Successes == 0 && s.ChallengesSeen > 0 {
		return DiagnosisIPReputationBlock, "all requests challenged, none succeeded — needs better exit network"
	}

	return DiagnosisTooFewData, "mixed results — need more data"
}

// Summary returns all hosts sorted by failure rate (worst first).
func (t *StatsTracker) Summary() []HostSummary {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]HostSummary, 0, len(t.hosts))
	for _, s := range t.hosts {
		diag, rec := diagnose(s)
		ipsSucceeded := 0
		for _, ip := range s.ExitIPs {
			if ip.Successes > 0 {
				ipsSucceeded++
			}
		}
		out = append(out, HostSummary{
			HostStats:        *s,
			ExitIPsTried:     len(s.ExitIPs),
			ExitIPsSucceeded: ipsSucceeded,
			Diagnosis:        diag,
			Recommendation:   rec,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		// Worst hosts first: lowest success rate
		ri := safeRate(out[i].Successes, out[i].TotalRequests)
		rj := safeRate(out[j].Successes, out[j].TotalRequests)
		if ri != rj {
			return ri < rj
		}
		return out[i].TotalRequests > out[j].TotalRequests
	})
	return out
}

// HostDetail returns the full stats for a host, or nil.
func (t *StatsTracker) HostDetail(host string) *HostStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.hosts[host]
	if !ok {
		return nil
	}
	cp := *s
	cp.ExitIPs = make(map[string]*ExitIPStats, len(s.ExitIPs))
	for k, v := range s.ExitIPs {
		vc := *v
		cp.ExitIPs[k] = &vc
	}
	return &cp
}

// ResetHost clears all stats for a host. Used by the manual
// override DELETE /.internal/stats/{host} endpoint.
func (t *StatsTracker) ResetHost(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.hosts, host)
}

// ShouldBlock returns true if the host has been diagnosed as
// unreachable and further requests would waste VPN bandwidth.
func (t *StatsTracker) ShouldBlock(host string) (bool, Diagnosis, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.hosts[host]
	if !ok {
		return false, "", ""
	}
	diag, rec := diagnose(s)
	switch diag {
	case DiagnosisCookieBinding, DiagnosisIPReputationBlock:
		return true, diag, rec
	default:
		return false, diag, rec
	}
}

func safeRate(num, den int64) float64 {
	if den == 0 {
		return 1.0
	}
	return float64(num) / float64(den)
}
