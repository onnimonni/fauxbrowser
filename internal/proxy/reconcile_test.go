package proxy

import (
	"strings"
	"testing"
)

func TestReconcileProfileSolverDisabled(t *testing.T) {
	// chromiumMajor=0 means solver disabled; behave like SelectProfile.
	got, err := ReconcileProfile("chrome131", 0, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "chrome131" {
		t.Errorf("got %q, want chrome131", got)
	}

	got, err = ReconcileProfile("", 0, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != DefaultProfile {
		t.Errorf("empty requested: got %q, want %q", got, DefaultProfile)
	}
}

func TestReconcileProfileAutoMatchesChromium(t *testing.T) {
	// Chromium 146, profile "latest" — should pick chrome146.
	got, err := ReconcileProfile("latest", 146, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "chrome146" {
		t.Errorf("got %q, want chrome146", got)
	}

	// Same for empty requested.
	got, err = ReconcileProfile("", 144, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "chrome144" {
		t.Errorf("got %q, want chrome144", got)
	}
}

func TestReconcileProfileAutoNewerChromiumStrict(t *testing.T) {
	// Chromium 200, no profile in table — strict mode errors.
	_, err := ReconcileProfile("latest", 200, false)
	if err == nil {
		t.Fatal("expected error for chromium major with no matching profile")
	}
	if !strings.Contains(err.Error(), "allow-version-mismatch") {
		t.Errorf("error should mention the override flag, got: %v", err)
	}
}

func TestReconcileProfileAutoNewerChromiumAllowed(t *testing.T) {
	// Chromium 200 with override — should fall back to DefaultProfile.
	got, err := ReconcileProfile("latest", 200, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != DefaultProfile {
		t.Errorf("got %q, want %q", got, DefaultProfile)
	}
}

func TestReconcileProfileExplicitMismatchStrict(t *testing.T) {
	// Explicit chrome131 with chromium 146 — strict mode errors.
	_, err := ReconcileProfile("chrome131", 146, false)
	if err == nil {
		t.Fatal("expected error for explicit profile / chromium mismatch")
	}
}

func TestReconcileProfileExplicitMismatchAllowed(t *testing.T) {
	// Explicit chrome131 with chromium 146 + override — keeps chrome131.
	got, err := ReconcileProfile("chrome131", 146, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "chrome131" {
		t.Errorf("got %q, want chrome131 (explicit kept)", got)
	}
}

func TestReconcileProfileExplicitMatchingChromium(t *testing.T) {
	got, err := ReconcileProfile("chrome146", 146, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "chrome146" {
		t.Errorf("got %q, want chrome146", got)
	}
}

func TestSelectProfileForMajor(t *testing.T) {
	p, ok := SelectProfileForMajor(146)
	if !ok {
		t.Fatal("chrome146 should be in table")
	}
	if p.Name != "chrome146" {
		t.Errorf("got %q", p.Name)
	}

	_, ok = SelectProfileForMajor(999)
	if ok {
		t.Error("chrome999 should not be in table")
	}
}
