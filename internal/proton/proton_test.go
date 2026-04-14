package proton

import (
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
	// Taint C as well — pool is empty.
	p.Taint("3.3.3.3")
	if _, ok := p.Next(); ok {
		t.Errorf("empty pool should report !ok")
	}
	// Advance time past cooldown, pool recovers.
	now += 20
	s, ok := p.Next()
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
