package main

import (
	"strings"
	"testing"

	"github.com/onnimonni/fauxbrowser/internal/config"
)

func TestIsNonLoopback(t *testing.T) {
	cases := map[string]bool{
		"":                   false, // empty = skip (AdminListen off)
		"127.0.0.1:18443":    false,
		"localhost:18443":    false,
		"[::1]:18443":        false,
		"0.0.0.0:18443":      true,
		"10.0.0.1:18443":     true,
		"192.168.1.1:18443":  true,
		"fauxbrowser:18443":  true, // unknown hostname → non-loopback
		"broken":             true, // unparseable → fail-safe
		"127.0.0.2:18443":    false, // entire 127/8 is loopback
	}
	for in, want := range cases {
		if got := isNonLoopback(in); got != want {
			t.Errorf("isNonLoopback(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSafetyCheckLoopbackOK(t *testing.T) {
	cfg := &config.Config{Listen: "127.0.0.1:18443"}
	if err := safetyCheck(cfg); err != nil {
		t.Errorf("loopback without auth should be OK, got %v", err)
	}
}

func TestSafetyCheckLoopbackWithAdminOK(t *testing.T) {
	cfg := &config.Config{
		Listen:      "127.0.0.1:18443",
		AdminListen: "127.0.0.1:18444",
	}
	if err := safetyCheck(cfg); err != nil {
		t.Errorf("loopback admin without auth should be OK, got %v", err)
	}
}

func TestSafetyCheckNonLoopbackRequiresProxyToken(t *testing.T) {
	cfg := &config.Config{Listen: "0.0.0.0:18443"}
	err := safetyCheck(cfg)
	if err == nil {
		t.Fatalf("non-loopback listen without token should fail")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Errorf("error should mention non-loopback: %v", err)
	}
	if !strings.Contains(err.Error(), "auth-token") {
		t.Errorf("error should mention auth-token: %v", err)
	}
}

func TestSafetyCheckNonLoopbackWithProxyTokenOK(t *testing.T) {
	cfg := &config.Config{
		Listen:    "0.0.0.0:18443",
		AuthToken: "secretvalue",
	}
	if err := safetyCheck(cfg); err != nil {
		t.Errorf("non-loopback with token should be OK, got %v", err)
	}
}

func TestSafetyCheckNonLoopbackAdminRequiresToken(t *testing.T) {
	cfg := &config.Config{
		Listen:      "127.0.0.1:18443",
		AdminListen: "0.0.0.0:18444",
	}
	err := safetyCheck(cfg)
	if err == nil {
		t.Fatalf("non-loopback admin without token should fail")
	}
	if !strings.Contains(err.Error(), "admin-token") {
		t.Errorf("error should mention admin-token: %v", err)
	}
}

func TestSafetyCheckNonLoopbackAdminWithTokenOK(t *testing.T) {
	cfg := &config.Config{
		Listen:      "127.0.0.1:18443",
		AdminListen: "0.0.0.0:18444",
		AdminToken:  "admin-secret",
	}
	if err := safetyCheck(cfg); err != nil {
		t.Errorf("non-loopback admin with token should be OK, got %v", err)
	}
}

// TestAdminPrefixCollisionSafe documents the invariant that admin
// endpoints live under a path segment that is illegal in DNS
// hostnames (leading dot), so no real upstream target can ever
// have a path starting with adminPrefix. This matters if an
// operator ever mounts the admin mux on the same listener as the
// proxy (not the default, but possible) — standard bare names
// like "/healthz" would clash with any target that happened to
// serve a /healthz endpoint, but /.internal/* cannot.
func TestAdminPrefixCollisionSafe(t *testing.T) {
	if !strings.HasPrefix(adminPrefix, "/.") {
		t.Errorf("adminPrefix must start with /. to stay collision-free with real HTTP targets; got %q", adminPrefix)
	}
	if !strings.HasSuffix(adminPrefix, "/") {
		t.Errorf("adminPrefix must end with / for http.ServeMux subtree matching; got %q", adminPrefix)
	}
	// Guard against typos like /.internal (no trailing slash) or
	// /internal (no leading dot).
	want := "/.internal/"
	if adminPrefix != want {
		t.Errorf("adminPrefix = %q, want %q (update docs if this changes)", adminPrefix, want)
	}
}
