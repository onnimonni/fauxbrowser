package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
}

func TestBearerAuthDisabled(t *testing.T) {
	// Empty token = auth disabled, pass-through.
	h := BearerAuth(okHandler(), "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("disabled auth code = %d, want 200", w.Code)
	}
}

func TestBearerAuthMissingHeader(t *testing.T) {
	h := BearerAuth(okHandler(), "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
	if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer ") {
		t.Errorf("WWW-Authenticate header missing or wrong: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestBearerAuthWrongToken(t *testing.T) {
	h := BearerAuth(okHandler(), "secret")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token code = %d, want 401", w.Code)
	}
}

func TestBearerAuthWrongScheme(t *testing.T) {
	h := BearerAuth(okHandler(), "secret")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("basic scheme code = %d, want 401", w.Code)
	}
}

func TestBearerAuthCorrectToken(t *testing.T) {
	h := BearerAuth(okHandler(), "secret")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("correct token code = %d, want 200", w.Code)
	}
}

func TestBearerAuthSchemeCaseInsensitive(t *testing.T) {
	h := BearerAuth(okHandler(), "secret")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("lowercase scheme code = %d, want 200", w.Code)
	}
}

func TestExtractBearer(t *testing.T) {
	cases := map[string]string{
		"":                         "",
		"Bearer":                   "",
		"Bearer ":                  "",
		"Bearer abc":               "abc",
		"bearer abc":               "abc",
		"Bearer    trimmed":        "trimmed",
		"Basic Zm9vOmJhcg==":       "",
		"Digest realm=x, nonce=y":  "",
	}
	for in, want := range cases {
		if got := extractBearer(in); got != want {
			t.Errorf("extractBearer(%q) = %q, want %q", in, got, want)
		}
	}
}
