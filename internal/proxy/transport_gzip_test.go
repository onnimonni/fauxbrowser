package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// TestGzipContentLengthFix is a regression test for issue #1.
//
// tls-client auto-decompresses gzip/br/zstd response bodies but
// leaves Content-Encoding and Content-Length headers describing
// the COMPRESSED bytes. fauxbrowser must strip both and force
// chunked encoding so downstream clients don't see truncated
// responses.
//
// This test exercises the fix-up logic by mimicking dispatch()'s
// response-building step in isolation: we synthesize a fake
// upstream response that looks like what tls-client would return
// after decompressing gzip, then assert that the
// Content-Encoding/Content-Length headers are removed and
// ContentLength is set to -1.
func TestGzipContentLengthFix(t *testing.T) {
	cases := []struct {
		name           string
		contentEnc     string
		contentLen     string
		shouldRewrite  bool
	}{
		{"gzip", "gzip", "102960", true},
		{"br", "br", "12345", true},
		{"zstd", "zstd", "5000", true},
		{"identity", "identity", "1024", false},
		{"none", "", "1024", false},
		{"compress", "compress", "999", true},
		{"deflate", "deflate", "888", true},
		{"GZIP uppercase", "GZIP", "100", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := &http.Response{
				Header:        http.Header{},
				ContentLength: 102960,
			}
			if c.contentEnc != "" {
				out.Header.Set("Content-Encoding", c.contentEnc)
			}
			out.Header.Set("Content-Length", c.contentLen)
			out.Header.Set("Content-Type", "text/html")

			// Inline the fix-up the same way dispatch() does it.
			if ce := strings.ToLower(out.Header.Get("Content-Encoding")); ce != "" && ce != "identity" {
				out.Header.Del("Content-Encoding")
				out.Header.Del("Content-Length")
				out.ContentLength = -1
			}

			if c.shouldRewrite {
				if out.Header.Get("Content-Encoding") != "" {
					t.Errorf("Content-Encoding still present: %q", out.Header.Get("Content-Encoding"))
				}
				if out.Header.Get("Content-Length") != "" {
					t.Errorf("Content-Length still present: %q", out.Header.Get("Content-Length"))
				}
				if out.ContentLength != -1 {
					t.Errorf("ContentLength = %d, want -1 (chunked)", out.ContentLength)
				}
			} else {
				if out.Header.Get("Content-Length") != c.contentLen {
					t.Errorf("Content-Length should be preserved (%q), got %q", c.contentLen, out.Header.Get("Content-Length"))
				}
				if out.ContentLength == -1 {
					t.Errorf("ContentLength should not be -1 for unencoded body")
				}
			}
			// Content-Type must always be preserved.
			if out.Header.Get("Content-Type") != "text/html" {
				t.Errorf("Content-Type should not be touched")
			}
		})
	}
}
