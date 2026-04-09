package proxy

import "testing"

func TestDiagnoseHealthy(t *testing.T) {
	tr := NewStatsTracker()
	for i := 0; i < 20; i++ {
		tr.RecordRequest("good.host", "1.2.3.4", 200)
	}
	diag, _ := tr.Diagnose("good.host")
	if diag != DiagnosisHealthy {
		t.Errorf("got %q, want healthy", diag)
	}
}

func TestDiagnoseTooFewData(t *testing.T) {
	tr := NewStatsTracker()
	tr.RecordRequest("new.host", "1.2.3.4", 200)
	diag, _ := tr.Diagnose("new.host")
	if diag != DiagnosisTooFewData {
		t.Errorf("got %q, want too_few_data", diag)
	}
}

func TestDiagnoseUnknownHost(t *testing.T) {
	tr := NewStatsTracker()
	diag, _ := tr.Diagnose("unknown.host")
	if diag != DiagnosisTooFewData {
		t.Errorf("got %q, want too_few_data for unknown host", diag)
	}
}

func TestDiagnoseSolverHandlesIt(t *testing.T) {
	tr := NewStatsTracker()
	// 7 successes + 3 challenges all solved
	for i := 0; i < 7; i++ {
		tr.RecordRequest("cf.host", "1.2.3.4", 200)
	}
	for i := 0; i < 3; i++ {
		tr.RecordRequest("cf.host", "1.2.3.4", 403)
		tr.RecordChallenge("cf.host", "1.2.3.4")
		tr.RecordSolverInvoked("cf.host")
		tr.RecordSolverSuccess("cf.host")
	}
	diag, _ := tr.Diagnose("cf.host")
	if diag != DiagnosisSolverHandlesIt {
		t.Errorf("got %q, want solver_handles_it", diag)
	}
}

func TestDiagnoseCookieBinding(t *testing.T) {
	tr := NewStatsTracker()
	// All requests challenged, solver fails across 3 IPs
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		tr.RecordRequest("pinned.host", ip, 403)
		tr.RecordChallenge("pinned.host", ip)
		tr.RecordSolverInvoked("pinned.host")
		tr.RecordSolverFailed("pinned.host")
	}
	diag, _ := tr.Diagnose("pinned.host")
	if diag != DiagnosisCookieBinding {
		t.Errorf("got %q, want cookie_binding", diag)
	}
}

func TestDiagnoseIPReputationBlock(t *testing.T) {
	tr := NewStatsTracker()
	// All requests challenged across 5 IPs, solver never invoked
	// (circuit already open or solver disabled)
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"} {
		tr.RecordRequest("blocked.host", ip, 403)
		tr.RecordChallenge("blocked.host", ip)
	}
	diag, _ := tr.Diagnose("blocked.host")
	if diag != DiagnosisIPReputationBlock {
		t.Errorf("got %q, want ip_reputation_block", diag)
	}
}

func TestDiagnoseRateLimited(t *testing.T) {
	tr := NewStatsTracker()
	for i := 0; i < 4; i++ {
		tr.RecordRequest("ratelimit.host", "1.2.3.4", 429)
	}
	for i := 0; i < 6; i++ {
		tr.RecordRequest("ratelimit.host", "1.2.3.4", 200)
	}
	diag, _ := tr.Diagnose("ratelimit.host")
	if diag != DiagnosisRateLimited {
		t.Errorf("got %q, want rate_limited", diag)
	}
}

func TestDiagnoseIPDependent(t *testing.T) {
	tr := NewStatsTracker()
	// IP A works, IP B doesn't
	for i := 0; i < 5; i++ {
		tr.RecordRequest("mixed.host", "1.1.1.1", 200)
	}
	for i := 0; i < 5; i++ {
		tr.RecordRequest("mixed.host", "2.2.2.2", 403)
		tr.RecordChallenge("mixed.host", "2.2.2.2")
	}
	diag, _ := tr.Diagnose("mixed.host")
	if diag != DiagnosisIPDependent {
		t.Errorf("got %q, want ip_dependent", diag)
	}
}

func TestShouldBlockOnCookieBinding(t *testing.T) {
	tr := NewStatsTracker()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		tr.RecordRequest("pinned.host", ip, 403)
		tr.RecordChallenge("pinned.host", ip)
		tr.RecordSolverInvoked("pinned.host")
		tr.RecordSolverFailed("pinned.host")
	}
	blocked, diag, _ := tr.ShouldBlock("pinned.host")
	if !blocked {
		t.Error("should block cookie_binding host")
	}
	if diag != DiagnosisCookieBinding {
		t.Errorf("diag = %q, want cookie_binding", diag)
	}
}

func TestShouldNotBlockHealthy(t *testing.T) {
	tr := NewStatsTracker()
	for i := 0; i < 10; i++ {
		tr.RecordRequest("good.host", "1.2.3.4", 200)
	}
	blocked, _, _ := tr.ShouldBlock("good.host")
	if blocked {
		t.Error("should not block healthy host")
	}
}

func TestSummarySort(t *testing.T) {
	tr := NewStatsTracker()
	// Host A: 100% success
	for i := 0; i < 5; i++ {
		tr.RecordRequest("good.host", "1.1.1.1", 200)
	}
	// Host B: 0% success
	for i := 0; i < 5; i++ {
		tr.RecordRequest("bad.host", "2.2.2.2", 403)
		tr.RecordChallenge("bad.host", "2.2.2.2")
	}
	summary := tr.Summary()
	if len(summary) != 2 {
		t.Fatalf("summary has %d entries, want 2", len(summary))
	}
	if summary[0].Host != "bad.host" {
		t.Errorf("worst host should be first, got %q", summary[0].Host)
	}
}

func TestResetHost(t *testing.T) {
	tr := NewStatsTracker()
	tr.RecordRequest("reset.host", "1.2.3.4", 200)
	tr.ResetHost("reset.host")
	if tr.HostDetail("reset.host") != nil {
		t.Error("host should be gone after reset")
	}
}
