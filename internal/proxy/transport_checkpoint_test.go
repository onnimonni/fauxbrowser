package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPeekCheckPoint(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    bool
	}{
		{
			name: "checkpoint block page",
			body: `<html><body>Access Temporarily Restricted<br>Incident Id: da25cb8e-1234</body></html>`,
			want: true,
		},
		{
			name: "checkpoint block mixed case",
			body: `ACCESS TEMPORARILY RESTRICTED incident id: abc123`,
			want: true,
		},
		{
			name: "plain 403 from nginx",
			body: `<html><title>403 Forbidden</title></html>`,
			want: false,
		},
		{
			name: "empty body",
			body: ``,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := io.NopCloser(strings.NewReader(c.body))
			got, restored := peekCheckPoint(body)
			if got != c.want {
				t.Errorf("peekCheckPoint = %v, want %v", got, c.want)
			}
			// Verify body is fully restored.
			b, _ := io.ReadAll(restored)
			if string(b) != c.body {
				t.Errorf("body not restored: got %q, want %q", string(b), c.body)
			}
		})
	}
}

func TestPeekCheckPointNilBody(t *testing.T) {
	got, body := peekCheckPoint(http.NoBody)
	if got {
		t.Error("expected false for http.NoBody")
	}
	if body != http.NoBody {
		t.Error("expected http.NoBody back")
	}
}
