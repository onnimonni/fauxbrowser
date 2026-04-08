// Package flaresolverr is a minimal, MIT-licensed JSON client for
// FlareSolverr (https://github.com/FlareSolverr/FlareSolverr).
//
// Only the subset of the API fauxbrowser needs is modeled: request.get
// with an optional per-request upstream proxy. Sessions are deliberately
// not supported here — fauxbrowser manages cookie caching itself in
// internal/solver.Cache.
package flaresolverr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL    string // e.g. http://127.0.0.1:8191
	HTTPClient *http.Client
}

// NewClient builds a Client with a sensible default timeout.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 120 * time.Second},
	}
}

// GetRequest models the request body for `cmd: request.get`.
type GetRequest struct {
	Cmd        string  `json:"cmd"`
	URL        string  `json:"url"`
	MaxTimeout int     `json:"maxTimeout,omitempty"`
	Proxy      *Proxy  `json:"proxy,omitempty"`
}

type Proxy struct {
	URL string `json:"url"`
}

// Response is the FlareSolverr top-level response envelope.
type Response struct {
	Status   string    `json:"status"` // "ok" on success
	Message  string    `json:"message"`
	Solution *Solution `json:"solution"`
}

// Solution is the browser-side result.
type Solution struct {
	URL       string    `json:"url"`
	Status    int       `json:"status"`
	Cookies   []Cookie  `json:"cookies"`
	UserAgent string    `json:"userAgent"`
	Response  string    `json:"response"`
}

type Cookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expiry"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite"`
}

// Get issues a request.get and returns the parsed Response.
func (c *Client) Get(ctx context.Context, targetURL, proxyURL string, maxTimeoutMillis int) (*Response, error) {
	if maxTimeoutMillis <= 0 {
		maxTimeoutMillis = 60000
	}
	body := GetRequest{
		Cmd:        "request.get",
		URL:        targetURL,
		MaxTimeout: maxTimeoutMillis,
	}
	if proxyURL != "" {
		body.Proxy = &Proxy{URL: proxyURL}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("flaresolverr: http %d: %s", resp.StatusCode, truncate(respBytes, 200))
	}
	var out Response
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("flaresolverr: decode: %w (body=%q)", err, truncate(respBytes, 200))
	}
	if out.Status != "ok" {
		return nil, fmt.Errorf("flaresolverr: %s", out.Message)
	}
	return &out, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
