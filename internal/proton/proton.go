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
	"strings"
	"sync"
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

// Pool is a thread-safe shuffled pool of servers with cooldown support.
// The rotator pulls from it; tainted servers are recycled back only after
// the cooldown expires.
type Pool struct {
	mu       sync.Mutex
	servers  []Server
	cursor   int
	tainted  map[string]int64 // entry_ip → unix ts when cooldown ends
	cooldown int64            // seconds
	now      func() int64     // injected for tests
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
		cooldown: cooldownSeconds,
		now:      nowFn,
	}
}

// Next returns the next server that isn't currently tainted, advancing
// the cursor. Returns false if every server is tainted. O(N) worst case.
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
	for i := 0; i < len(p.servers); i++ {
		s := p.servers[p.cursor]
		p.cursor = (p.cursor + 1) % len(p.servers)
		if _, bad := p.tainted[s.EntryIP]; !bad {
			return s, true
		}
	}
	return Server{}, false
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
