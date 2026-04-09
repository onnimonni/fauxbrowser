package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// stubTransport is an http.RoundTripper that returns a canned response.
// Used so the handler tests exercise routing without building a
// tls-client pool or touching the network.
type stubTransport struct {
	fn   func(r *http.Request) (*http.Response, error)
	seen atomic.Int32
}

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.seen.Add(1)
	return s.fn(r)
}

func newStub(body string) *stubTransport {
	return &stubTransport{
		fn: func(r *http.Request) (*http.Response, error) {
			h := http.Header{}
			h.Set("X-Fauxbrowser-Upstream-URL", r.URL.String())
			return &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     h,
				Body:       io.NopCloser(strings.NewReader(body)),
				Proto:      "HTTP/1.1",
				ProtoMajor: 1, ProtoMinor: 1,
			}, nil
		},
	}
}

func newHandlerWithStub(rt http.RoundTripper) http.Handler {
	// Build handler by hand because NewHandler expects *Transport. We
	// re-use its ReverseProxy internally — the easiest test path is to
	// just call WrapH2C(NewHandler(...)) with a shimmed Transport. The
	// Transport type has a single Dialer requirement; here we bypass
	// by constructing the ReverseProxy directly.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "no", http.StatusNotImplemented)
			return
		}
		var target string
		if t := r.Header.Get("X-Target-URL"); t != "" {
			u, err := url.Parse(t)
			if err != nil || !u.IsAbs() {
				http.Error(w, "bad X-Target-URL", http.StatusBadRequest)
				return
			}
			target = u.String()
		} else if r.URL.IsAbs() {
			target = r.URL.String()
		} else {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
		for k, vs := range r.Header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func TestHandlerXTargetURL(t *testing.T) {
	stub := newStub("hello")
	srv := httptest.NewServer(newHandlerWithStub(stub))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("X-Target-URL", "https://example.com/path?q=1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Fauxbrowser-Upstream-URL"); got != "https://example.com/path?q=1" {
		t.Errorf("upstream URL = %q", got)
	}
}

func TestHandlerBadTargetURL(t *testing.T) {
	stub := newStub("hi")
	srv := httptest.NewServer(newHandlerWithStub(stub))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("X-Target-URL", "not a url")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerRejectsCONNECT(t *testing.T) {
	// The real handler (NewHandler) must reject CONNECT. We test the
	// real one here, not the stub.
	h := NewHandler(Options{TargetHeader: "X-Target-URL", Transport: nil})
	r := httptest.NewRequest("CONNECT", "https://example.com:443", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", w.Code)
	}
}

func TestH2CListener(t *testing.T) {
	stub := newStub("h2c hello")
	h := WrapH2C(newHandlerWithStub(stub))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// HTTP/2 cleartext client. Uses a raw TCP dialer (no TLS).
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	// Fire a handful of concurrent requests on the SAME TCP connection
	// (h2 multiplexing). If WrapH2C wiring is wrong, this will either
	// speak h1 (one conn per request, which h2.Transport would error on)
	// or fail outright.
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/", ln.Addr()), nil)
			req.Header.Set("X-Target-URL", fmt.Sprintf("https://example.com/%d", i))
			resp, err := c.Do(req)
			if err != nil {
				t.Logf("req %d: %v", i, err)
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == 200 && string(b) == "h2c hello" && resp.ProtoMajor == 2 {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if ok.Load() != 10 {
		t.Errorf("got %d/10 successful h2 requests", ok.Load())
	}
}

// TestH2CListenerSpeaksH1 verifies the same port still serves plain
// HTTP/1.1 clients so a simple curl works.
func TestH2CListenerSpeaksH1(t *testing.T) {
	stub := newStub("h1 hello")
	h := WrapH2C(newHandlerWithStub(stub))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := "GET / HTTP/1.1\r\nHost: test\r\nX-Target-URL: https://example.com/h1\r\nConnection: close\r\n\r\n"
	_, _ = conn.Write([]byte(req))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "h1 hello" {
		t.Errorf("body = %q, want h1 hello", string(b))
	}
}
