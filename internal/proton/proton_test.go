package proton

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedSnapshot(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	if c.Len() == 0 {
		t.Fatalf("catalog is empty")
	}
	// Every server must have entry_ip + pubkey (the snapshot generator
	// filters these out, so any zero value is a regression).
	for _, s := range c.All() {
		if s.EntryIP == "" || s.Pubkey == "" || s.Name == "" || s.Country == "" {
			t.Errorf("bad server: %+v", s)
		}
		if s.Tier != TierFree && s.Tier != TierPlus {
			t.Errorf("unexpected tier %d: %+v", s.Tier, s)
		}
	}
	// ExpectedPubkey must resolve for every server's EntryIP.
	for _, s := range c.All() {
		got, ok := c.ExpectedPubkey(s.EntryIP)
		if !ok || got != s.Pubkey {
			t.Errorf("ExpectedPubkey mismatch for %s: got %q ok=%v, want %q", s.EntryIP, got, ok, s.Pubkey)
		}
	}
	// Unknown IPs must be unknown.
	if _, ok := c.ExpectedPubkey("127.0.0.1"); ok {
		t.Errorf("ExpectedPubkey(127.0.0.1) should be unknown")
	}
}

func TestFilterByCountry(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	nl := c.Filter(TierFreeOnly, []string{"NL"}, nil)
	if len(nl) == 0 {
		t.Fatalf("no NL servers in snapshot")
	}
	for _, s := range nl {
		if strings.ToUpper(s.Country) != "NL" {
			t.Errorf("non-NL leaked: %+v", s)
		}
	}
	// Lowercase input should still work.
	nl2 := c.Filter(TierFreeOnly, []string{"nl"}, nil)
	if len(nl2) != len(nl) {
		t.Errorf("country filter is case-sensitive")
	}
	multi := c.Filter(TierFreeOnly, []string{"NL", "JP"}, nil)
	if len(multi) <= len(nl) {
		t.Errorf("NL+JP filter should include more than NL alone")
	}
}

func TestFilterByContinent(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	eu := c.Filter(TierFreeOnly, nil, []string{"EU"})
	if len(eu) == 0 {
		t.Fatalf("no EU servers")
	}
	for _, s := range eu {
		if ContinentOf(s.Country) != "EU" {
			t.Errorf("non-EU leaked: %+v (continent=%s)", s, ContinentOf(s.Country))
		}
	}
	// Country + continent combined: country wins by restricting further.
	both := c.Filter(TierFreeOnly, []string{"NL"}, []string{"EU"})
	nl := c.Filter(TierFreeOnly, []string{"NL"}, nil)
	if len(both) != len(nl) {
		t.Errorf("NL ∩ EU should equal NL: got %d vs %d", len(both), len(nl))
	}
}

func TestFilterEmpty(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	all := c.Filter(TierAll, nil, nil)
	if len(all) != c.Len() {
		t.Errorf("empty TierAll filter should return all: got %d vs %d", len(all), c.Len())
	}
}

func TestTierFilter(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	free := c.Filter(TierFreeOnly, nil, nil)
	paid := c.Filter(TierPlusOnly, nil, nil)
	all := c.Filter(TierAll, nil, nil)
	if len(free) == 0 || len(paid) == 0 {
		t.Fatalf("expected both tiers present: free=%d paid=%d", len(free), len(paid))
	}
	if len(free)+len(paid) != len(all) {
		t.Errorf("free+paid != all: %d + %d != %d", len(free), len(paid), len(all))
	}
	for _, s := range free {
		if s.Tier != TierFree {
			t.Errorf("free filter leaked tier=%d: %+v", s.Tier, s)
		}
	}
	for _, s := range paid {
		if s.Tier != TierPlus {
			t.Errorf("paid filter leaked tier=%d: %+v", s.Tier, s)
		}
	}
}

func TestParseTierFilter(t *testing.T) {
	cases := map[string]TierFilter{
		"":     TierFreeOnly,
		"free": TierFreeOnly,
		"FREE": TierFreeOnly,
		"paid": TierPlusOnly,
		"plus": TierPlusOnly,
		"all":  TierAll,
		"both": TierAll,
		"junk": TierFreeOnly, // unknown → default
	}
	for in, want := range cases {
		if got := ParseTierFilter(in); got != want {
			t.Errorf("ParseTierFilter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestContinentOf(t *testing.T) {
	cases := map[string]string{
		"NL": "EU", "DE": "EU", "JP": "AS", "US": "NA", "CA": "NA",
		"BR": "SA", "AU": "OC", "ZA": "AF", "zz": "",
	}
	for in, want := range cases {
		if got := ContinentOf(in); got != want {
			t.Errorf("ContinentOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPoolNextCyclesAndTaints(t *testing.T) {
	servers := []Server{
		{Name: "A", EntryIP: "1.1.1.1", Pubkey: "a"},
		{Name: "B", EntryIP: "2.2.2.2", Pubkey: "b"},
		{Name: "C", EntryIP: "3.3.3.3", Pubkey: "c"},
	}
	now := int64(1000)
	p := NewPool(servers, 10, func() int64 { return now })
	// With equal weights, all 3 servers must appear within 100 iterations
	// (probability of missing any one is (2/3)^100 ≈ 2e-18 — negligible).
	seen := map[string]int{}
	for i := 0; i < 100; i++ {
		s, ok := p.Next()
		if !ok {
			t.Fatalf("Next returned !ok on iteration %d", i)
		}
		seen[s.Name]++
	}
	if len(seen) != 3 {
		t.Errorf("expected to see all 3 servers in 100 iterations: %+v", seen)
	}
	// Taint A + B, only C should come out.
	p.Taint("1.1.1.1")
	p.Taint("2.2.2.2")
	for i := 0; i < 5; i++ {
		s, ok := p.Next()
		if !ok {
			t.Fatalf("Next should still return C")
		}
		if s.Name != "C" {
			t.Errorf("got %q, want C", s.Name)
		}
	}
	// Taint C as well — all servers tainted. Next falls back to best-scored.
	p.Taint("3.3.3.3")
	// Available() reports 0 — all tainted.
	if p.Available() != 0 {
		t.Errorf("Available should be 0 when all tainted, got %d", p.Available())
	}
	// Next() still returns a server (the fallback path).
	s, ok := p.Next()
	if !ok {
		t.Fatalf("Next should fall back to best-scored tainted server, got !ok")
	}
	_ = s
	// Advance time past cooldown, pool recovers normally.
	now += 20
	s, ok = p.Next()
	if !ok {
		t.Fatalf("pool should recover after cooldown")
	}
	_ = s
	if p.Available() != 3 {
		t.Errorf("Available = %d, want 3", p.Available())
	}
}

func TestPoolScoreWeighting(t *testing.T) {
	// A has been repeatedly blocked, B is neutral, C has good history.
	// After many Next() calls C should be picked most often, A least.
	servers := []Server{
		{Name: "A", EntryIP: "1.1.1.1", Pubkey: "a"},
		{Name: "B", EntryIP: "2.2.2.2", Pubkey: "b"},
		{Name: "C", EntryIP: "3.3.3.3", Pubkey: "c"},
	}
	p := NewPool(servers, 10, nil)

	// Drive A's score down (many blocks).
	for i := 0; i < 10; i++ {
		p.RecordOutcome("1.1.1.1", false)
	}
	// Drive C's score up (many successes).
	for i := 0; i < 10; i++ {
		p.RecordOutcome("3.3.3.3", true)
	}
	// B stays at neutral (0.5).

	scoreA := p.Score("1.1.1.1")
	scoreB := p.Score("2.2.2.2")
	scoreC := p.Score("3.3.3.3")
	if scoreA >= scoreB {
		t.Errorf("blocked A score (%v) should be below neutral B (%v)", scoreA, scoreB)
	}
	if scoreB >= scoreC {
		t.Errorf("neutral B score (%v) should be below good C (%v)", scoreB, scoreC)
	}

	// Sample 10000 picks — C should dominate, A should be rare.
	counts := map[string]int{}
	for i := 0; i < 10000; i++ {
		s, ok := p.Next()
		if !ok {
			t.Fatal("pool exhausted unexpectedly")
		}
		counts[s.Name]++
	}
	if counts["C"] <= counts["B"] {
		t.Errorf("C (good) should be picked more than B (neutral): C=%d B=%d", counts["C"], counts["B"])
	}
	if counts["B"] <= counts["A"] {
		t.Errorf("B (neutral) should be picked more than A (blocked): B=%d A=%d", counts["B"], counts["A"])
	}
	// A must still be reachable (score floor guarantees some picks).
	if counts["A"] == 0 {
		t.Errorf("blocked A should still get some picks via score floor, got 0")
	}
}

func TestPoolScoreNeutralForUnknown(t *testing.T) {
	p := NewPool(nil, 10, nil)
	if got := p.Score("1.2.3.4"); got != scoreNeutral {
		t.Errorf("unknown IP score = %v, want %v (neutral)", got, scoreNeutral)
	}
}

func TestPoolEmpty(t *testing.T) {
	p := NewPool(nil, 10, nil)
	if _, ok := p.Next(); ok {
		t.Errorf("empty pool Next should be !ok")
	}
}

// TestPoolExhaustionFallback verifies that when all servers are tainted,
// Next() falls back to the best-scored one instead of returning !ok.
// This prevents hard bootstrap failures when a transient condition
// (e.g. noisy DNS probe) taints the entire pool simultaneously.
func TestPoolExhaustionFallback(t *testing.T) {
	servers := []Server{
		{Name: "A", EntryIP: "1.1.1.1", Pubkey: "a"},
		{Name: "B", EntryIP: "2.2.2.2", Pubkey: "b"},
		{Name: "C", EntryIP: "3.3.3.3", Pubkey: "c"},
	}
	now := int64(1000)
	p := NewPool(servers, 300, func() int64 { return now })

	// Give C the best score and A the worst.
	for i := 0; i < 10; i++ {
		p.RecordOutcome("3.3.3.3", true)  // C: high score
		p.RecordOutcome("1.1.1.1", false) // A: low score
	}
	// B stays neutral.

	// Taint all three.
	p.Taint("1.1.1.1")
	p.Taint("2.2.2.2")
	p.Taint("3.3.3.3")

	if p.Available() != 0 {
		t.Fatalf("expected Available=0, got %d", p.Available())
	}

	// First fallback pick must be the highest-scored server (C).
	s, ok := p.Next()
	if !ok {
		t.Fatalf("Next should return a fallback server when all tainted, got !ok")
	}
	if s.Name != "C" {
		t.Errorf("fallback should pick best-scored server C, got %q", s.Name)
	}

	// Simulate the rotator: probe failed → record outcome + re-taint.
	// RecordOutcome(false) lowers C's score so the next fallback picks B.
	p.RecordOutcome("3.3.3.3", false)
	p.RecordOutcome("3.3.3.3", false)
	p.RecordOutcome("3.3.3.3", false)
	p.Taint("3.3.3.3")
	s2, ok := p.Next()
	if !ok {
		t.Fatalf("second fallback pick should still work, got !ok")
	}
	if s2.Name != "B" {
		t.Errorf("second fallback should pick neutral B (next best after degraded C), got %q", s2.Name)
	}

	// Verify that once C is not re-tainted (bootstrap succeeded), normal weighted
	// selection resumes. Both B and C are now untainted (B's taint lifted by fallback).
	counts := map[string]int{}
	for i := 0; i < 1000; i++ {
		s, ok := p.Next()
		if !ok {
			t.Fatalf("unexpected !ok after fallback lifted taint")
		}
		counts[s.Name]++
	}
	// B and C should dominate (A has lowest score, but score floor ensures some picks).
	if counts["A"] >= counts["B"] {
		t.Errorf("low-scored A should appear less than neutral B: A=%d B=%d", counts["A"], counts["B"])
	}
}

// TestPoolFallbackAlwaysReturnsServer verifies that Next() never returns !ok
// when there are servers in the pool, even if all are tainted. This is the
// core invariant of the exhaustion-fallback feature.
func TestPoolFallbackAlwaysReturnsServer(t *testing.T) {
	servers := []Server{
		{Name: "A", EntryIP: "1.1.1.1", Pubkey: "a"},
		{Name: "B", EntryIP: "2.2.2.2", Pubkey: "b"},
	}
	now := int64(1000)
	p := NewPool(servers, 300, func() int64 { return now })

	// Taint both (all exhausted).
	p.Taint("1.1.1.1")
	p.Taint("2.2.2.2")

	// Simulate 20 rotation attempts where every probe fails.
	// Next() should always return a server and never !ok.
	for i := 0; i < 20; i++ {
		s, ok := p.Next()
		if !ok {
			t.Fatalf("iteration %d: Next returned !ok with servers in pool", i)
		}
		// Rotator records probe failure and re-taints.
		p.RecordOutcome(s.EntryIP, false)
		p.Taint(s.EntryIP)
	}
}

// TestPoolFallbackPrefersBestScore verifies that when all servers are tainted,
// the fallback consistently returns the highest-scored server first.
func TestPoolFallbackPrefersBestScore(t *testing.T) {
	servers := []Server{
		{Name: "A", EntryIP: "1.1.1.1", Pubkey: "a"},
		{Name: "B", EntryIP: "2.2.2.2", Pubkey: "b"},
		{Name: "C", EntryIP: "3.3.3.3", Pubkey: "c"},
	}
	now := int64(1000)
	p := NewPool(servers, 300, func() int64 { return now })

	// Give C a notably higher score than B and A.
	for i := 0; i < 15; i++ {
		p.RecordOutcome("3.3.3.3", true)
	}
	for i := 0; i < 15; i++ {
		p.RecordOutcome("1.1.1.1", false)
	}

	// Taint all.
	p.Taint("1.1.1.1")
	p.Taint("2.2.2.2")
	p.Taint("3.3.3.3")

	// Repeated calls with immediate re-taint should keep returning C (best score).
	for i := 0; i < 5; i++ {
		s, ok := p.Next()
		if !ok {
			t.Fatalf("iteration %d: got !ok", i)
		}
		if s.Name != "C" {
			t.Errorf("iteration %d: expected best-scored C, got %q", i, s.Name)
		}
		// Re-taint without recording outcome (score unchanged → C stays best).
		p.Taint(s.EntryIP)
	}

	// After recording many failures on C, its score drops and B (neutral) becomes best.
	for i := 0; i < 20; i++ {
		p.RecordOutcome("3.3.3.3", false)
	}
	p.Taint("3.3.3.3")

	s, ok := p.Next()
	if !ok {
		t.Fatalf("fallback after score change: got !ok")
	}
	if s.Name != "B" {
		t.Errorf("after C degraded, expected neutral B, got %q", s.Name)
	}
}

func TestPoolScorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scores.json")

	p := NewPool([]Server{{Name: "A", EntryIP: "1.1.1.1", Pubkey: "a"}}, 10, nil)

	// Record some outcomes then save.
	for i := 0; i < 5; i++ {
		p.RecordOutcome("1.1.1.1", true)
	}
	savedScore := p.Score("1.1.1.1")
	if savedScore <= scoreNeutral {
		t.Fatalf("expected score above neutral after successes, got %v", savedScore)
	}

	if err := p.SaveScores(); err != nil {
		t.Fatalf("SaveScores: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("SaveScores with no path set should not create a file")
	}

	// Now with path configured.
	if err := p.LoadScores(path); err != nil {
		t.Fatalf("LoadScores on missing file: %v", err)
	}
	if err := p.SaveScores(); err != nil {
		t.Fatalf("SaveScores: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected scores file at %q: %v", path, err)
	}

	// New pool, load the saved scores, verify they match.
	p2 := NewPool([]Server{{Name: "A", EntryIP: "1.1.1.1", Pubkey: "a"}}, 10, nil)
	if err := p2.LoadScores(path); err != nil {
		t.Fatalf("LoadScores: %v", err)
	}
	if got := p2.Score("1.1.1.1"); got != savedScore {
		t.Errorf("restored score = %v, want %v", got, savedScore)
	}
}
