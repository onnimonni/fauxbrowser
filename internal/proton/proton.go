// Package proton is a minimal client for discovering free-tier ProtonVPN
// WireGuard servers.
//
// Proton's /vpn/logicals API now requires an authenticated session, so we
// ship a baked-in snapshot of free-tier physical servers (name, country,
// entry IP, and X25519 peer public key). The snapshot is the exact data
// a fresh account would receive; it's refreshed every time this file is
// regenerated (see internal/proton/gen). At runtime fauxbrowser uses the
// embedded list by default and only considers a refresh when no server
// in the list accepts a WireGuard handshake.
//
// Key reuse: verified empirically against Proton free servers on 2026-04-08,
// one WireGuard client private key (from an existing wg-quick .conf)
// authenticates against every free server in the snapshot regardless of
// country. The peer public key is pinned per server and verified
// cryptographically by the WireGuard handshake itself — a mismatch simply
// fails the handshake and the rotator moves on to the next entry.
package proton

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed snapshot.json
var snapshotRaw []byte

// Server is one Proton physical server.
type Server struct {
	Name    string `json:"name"`    // e.g. "NL-FREE#15"
	Tier    int    `json:"tier"`    // 0 = free, 2 = plus (paid)
	Country string `json:"country"` // ISO alpha-2 exit country
	City    string `json:"city"`
	Domain  string `json:"domain"` // e.g. "node-nl-05.protonvpn.net"
	EntryIP string `json:"entry_ip"`
	ExitIP  string `json:"exit_ip"`
	Pubkey  string `json:"pubkey"` // base64 X25519 peer public key
}

// Tier constants.
const (
	TierFree = 0
	TierPlus = 2
)

// snapshot is the on-disk snapshot format.
type snapshot struct {
	FetchedAt string   `json:"fetched_at"`
	Source    string   `json:"source"`
	Servers   []Server `json:"servers"`
}

// Catalog is a queryable view over the embedded snapshot.
type Catalog struct {
	fetched string
	all     []Server
	// pubkeyByIP is the peer-pinning map used by the rotator to verify
	// that the server we dial matches the key we expect.
	pubkeyByIP map[string]string
}

// Embedded returns a Catalog built from the baked-in snapshot.
func Embedded() (*Catalog, error) {
	var s snapshot
	if err := json.Unmarshal(snapshotRaw, &s); err != nil {
		return nil, fmt.Errorf("decode embedded snapshot: %w", err)
	}
	return fromSnapshot(&s), nil
}

func fromSnapshot(s *snapshot) *Catalog {
	c := &Catalog{
		fetched:    s.FetchedAt,
		all:        s.Servers,
		pubkeyByIP: make(map[string]string, len(s.Servers)),
	}
	for _, srv := range s.Servers {
		if srv.EntryIP != "" && srv.Pubkey != "" {
			c.pubkeyByIP[srv.EntryIP] = srv.Pubkey
		}
	}
	return c
}

// FetchedAt is the date the snapshot was captured.
func (c *Catalog) FetchedAt() string { return c.fetched }

// All returns every server in the catalog.
func (c *Catalog) All() []Server { return append([]Server(nil), c.all...) }

// Len returns the number of servers in the catalog.
func (c *Catalog) Len() int { return len(c.all) }

// ExpectedPubkey returns the pinned X25519 public key for an entry IP.
// The second return is false if the IP is unknown to the catalog, in
// which case the rotator MUST refuse to dial it.
func (c *Catalog) ExpectedPubkey(entryIP string) (string, bool) {
	k, ok := c.pubkeyByIP[entryIP]
	return k, ok
}

// TierFilter controls which tiers Filter includes.
type TierFilter int

const (
	// TierFreeOnly keeps only free-tier (Tier=0) servers. This is the
	// default because most use cases assume a free Proton account whose
	// WireGuard key has only been verified to authenticate against free
	// peers.
	TierFreeOnly TierFilter = iota
	// TierPlusOnly keeps only Plus (Tier=2) servers. Requires a paid
	// account whose key is registered on paid peers.
	TierPlusOnly
	// TierAll keeps everything in the catalog.
	TierAll
)

// ParseTierFilter parses a "free"/"paid"/"plus"/"all" string (case-
// insensitive). Unknown values fall back to TierFreeOnly.
func ParseTierFilter(s string) TierFilter {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "free":
		return TierFreeOnly
	case "paid", "plus":
		return TierPlusOnly
	case "all", "any", "both":
		return TierAll
	default:
		return TierFreeOnly
	}
}

// Filter returns servers matching the given tier, country, and
// continent. Empty country/continent lists mean "no restriction".
// Country codes are ISO alpha-2 (uppercased before comparison).
func (c *Catalog) Filter(tier TierFilter, countries, continents []string) []Server {
	cs := normalizeSet(countries)
	cn := normalizeSet(continents)
	out := make([]Server, 0, len(c.all))
	for _, s := range c.all {
		switch tier {
		case TierFreeOnly:
			if s.Tier != TierFree {
				continue
			}
		case TierPlusOnly:
			if s.Tier != TierPlus {
				continue
			}
		}
		if len(cs) > 0 {
			if _, ok := cs[strings.ToUpper(s.Country)]; !ok {
				continue
			}
		}
		if len(cn) > 0 {
			cont := ContinentOf(s.Country)
			if _, ok := cn[cont]; !ok {
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

func normalizeSet(xs []string) map[string]struct{} {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		x = strings.ToUpper(strings.TrimSpace(x))
		if x != "" {
			m[x] = struct{}{}
		}
	}
	return m
}

// scoreFloor is the minimum reputation weight an IP retains even after
// repeated bot-blocks. This prevents a previously-bad IP from being
// permanently excluded so it can recover if conditions improve.
const scoreFloor = 0.05

// scoreNeutral is the starting reputation for a newly-seen IP (no data).
const scoreNeutral = 0.5

// scoreAlpha is the EMA smoothing factor for RecordOutcome updates.
// Higher = faster adaptation (new outcomes matter more).
const scoreAlpha = 0.3

// Pool is a thread-safe pool of servers with cooldown support and
// runtime IP reputation scoring. The rotator pulls from it; tainted
// servers are recycled after the cooldown expires. Within the
// non-tainted set, servers are picked by weighted-random selection
// proportional to their reputation score so known-good IPs are
// preferred while still giving penalised IPs a chance to recover.
type Pool struct {
	mu       sync.Mutex
	servers  []Server
	tainted  map[string]int64   // entry_ip → unix ts when cooldown ends
	scores   map[string]float64 // entry_ip → EMA reputation [0.0, 1.0]
	cooldown int64              // seconds
	now      func() int64       // injected for tests

	scoresPath  string        // path for score persistence; empty = disabled
	saveTimer   *time.Timer   // debounce timer for async save
	savePending bool          // true while timer is armed
}

// NewPool returns a randomly-ordered Pool of the given servers.
func NewPool(servers []Server, cooldownSeconds int64, nowFn func() int64) *Pool {
	cp := append([]Server(nil), servers...)
	rand.Shuffle(len(cp), func(i, j int) { cp[i], cp[j] = cp[j], cp[i] })
	if nowFn == nil {
		nowFn = defaultNow
	}
	return &Pool{
		servers:  cp,
		tainted:  make(map[string]int64),
		scores:   make(map[string]float64),
		cooldown: cooldownSeconds,
		now:      nowFn,
	}
}

// scoreFor returns the effective weight for an entry IP. Caller holds mu.
func (p *Pool) scoreFor(entryIP string) float64 {
	s, ok := p.scores[entryIP]
	if !ok {
		return scoreNeutral
	}
	if s < scoreFloor {
		return scoreFloor
	}
	return s
}

// RecordOutcome updates the EMA reputation score for an exit IP.
// success=true raises the score toward 1.0; success=false lowers it
// toward 0.0. Thread-safe. Called by the transport after each response:
// a bot-block (429, WAF challenge) records false; a 2xx records true.
// If a scoresPath is configured, schedules a debounced async save.
func (p *Pool) RecordOutcome(entryIP string, success bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.scoreFor(entryIP)
	outcome := 0.0
	if success {
		outcome = 1.0
	}
	p.scores[entryIP] = cur + scoreAlpha*(outcome-cur)
	p.scheduleSaveLocked()
}

// scheduleSaveLocked arms/resets the debounce timer. Caller holds mu.
func (p *Pool) scheduleSaveLocked() {
	if p.scoresPath == "" {
		return
	}
	const debounce = 5 * time.Second
	if p.savePending {
		p.saveTimer.Reset(debounce)
		return
	}
	p.savePending = true
	p.saveTimer = time.AfterFunc(debounce, func() {
		p.mu.Lock()
		p.savePending = false
		path := p.scoresPath
		snap := make(map[string]float64, len(p.scores))
		for k, v := range p.scores {
			snap[k] = v
		}
		p.mu.Unlock()
		if err := saveScoresFile(path, snap); err != nil {
			// Non-fatal: next RecordOutcome will retry.
			_ = err
		}
	})
}

// SetScoresPath configures where reputation scores are persisted.
// Call before the pool is used; safe to call concurrently otherwise.
func (p *Pool) SetScoresPath(path string) {
	p.mu.Lock()
	p.scoresPath = path
	p.mu.Unlock()
}

// LoadScores reads a previously saved scores file and merges it into
// the pool. Unknown IPs are ignored. Call once at startup before
// the pool is handed to the rotator.
func (p *Pool) LoadScores(path string) error {
	// Always record the path so SaveScores knows where to write,
	// even if the file doesn't exist yet (first run).
	p.mu.Lock()
	p.scoresPath = path
	p.mu.Unlock()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // first run — fine
	}
	if err != nil {
		return fmt.Errorf("proton: load scores %q: %w", path, err)
	}
	var snap map[string]float64
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("proton: parse scores %q: %w", path, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range snap {
		if v >= 0 && v <= 1.0 {
			p.scores[k] = v
		}
	}
	return nil
}

// SaveScores flushes the current scores to disk immediately. Intended
// for graceful shutdown so no data is lost between debounce flushes.
func (p *Pool) SaveScores() error {
	p.mu.Lock()
	if p.scoresPath == "" {
		p.mu.Unlock()
		return nil
	}
	// Cancel pending debounce timer if any.
	if p.savePending && p.saveTimer != nil {
		p.saveTimer.Stop()
		p.savePending = false
	}
	path := p.scoresPath
	snap := make(map[string]float64, len(p.scores))
	for k, v := range p.scores {
		snap[k] = v
	}
	p.mu.Unlock()
	return saveScoresFile(path, snap)
}

func saveScoresFile(path string, scores map[string]float64) error {
	data, err := json.Marshal(scores)
	if err != nil {
		return err
	}
	// Write to temp file then rename for atomicity.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("proton: write scores %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("proton: rename scores: %w", err)
	}
	return nil
}

// Score returns the current reputation score for an entry IP.
// Returns scoreNeutral (0.5) for IPs with no recorded outcomes.
func (p *Pool) Score(entryIP string) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.scoreFor(entryIP)
}

// Scores returns a copy of all known IP → reputation score pairs.
// IPs with no observations are not included. For the admin endpoint.
func (p *Pool) Scores() map[string]float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]float64, len(p.scores))
	for ip, s := range p.scores {
		if s < scoreFloor {
			s = scoreFloor
		}
		out[ip] = s
	}
	return out
}

// Next picks a server from the non-tainted pool using weighted-random
// selection: each server's probability is proportional to its reputation
// score. IPs with more bot-block events get lower weights; unknown IPs
// start at 0.5 (neutral). Returns false only when every server is
// tainted (WireGuard-level failures), not when scores are merely low.
func (p *Pool) Next() (Server, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.servers) == 0 {
		return Server{}, false
	}
	now := p.now()
	// Expire tainted entries.
	for ip, until := range p.tainted {
		if now >= until {
			delete(p.tainted, ip)
		}
	}
	// Build weighted candidate list from non-tainted servers.
	type candidate struct {
		srv    Server
		weight float64
	}
	cands := make([]candidate, 0, len(p.servers))
	totalWeight := 0.0
	for _, s := range p.servers {
		if _, bad := p.tainted[s.EntryIP]; bad {
			continue
		}
		w := p.scoreFor(s.EntryIP)
		cands = append(cands, candidate{s, w})
		totalWeight += w
	}
	if len(cands) == 0 {
		return Server{}, false
	}
	// Weighted random pick.
	r := rand.Float64() * totalWeight
	accum := 0.0
	for _, c := range cands {
		accum += c.weight
		if r < accum {
			return c.srv, true
		}
	}
	// Floating-point rounding fallback: return last candidate.
	return cands[len(cands)-1].srv, true
}

// Taint marks a server's entry IP as unusable for the pool's cooldown
// window. Safe to call concurrently.
func (p *Pool) Taint(entryIP string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tainted[entryIP] = p.now() + p.cooldown
}

// Size returns total servers (including currently tainted).
func (p *Pool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.servers)
}

// Available returns the count of non-tainted servers right now.
func (p *Pool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	avail := 0
	for _, s := range p.servers {
		until, bad := p.tainted[s.EntryIP]
		if !bad || now >= until {
			avail++
		}
	}
	return avail
}

func defaultNow() int64 {
	return nowUnix()
}
