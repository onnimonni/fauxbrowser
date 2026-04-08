# fauxbrowser

Tiny HTTP proxy that forges browser TLS fingerprints for `curl` or any
HTTP client. Internally it re-issues every request through
[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) (a
patched utls fork) so the outgoing TLS handshake, JA3/JA4 fingerprint,
and default header set all match a real Chrome / Firefox / Safari build.
Optionally chains through an upstream HTTP proxy such as
[qdm12/gluetun](https://github.com/qdm12/gluetun) so every egress exits
via a WireGuard / OpenVPN tunnel.

## Three ways to talk to it

| Mode             | Client invocation                                                | CA trust |
|------------------|------------------------------------------------------------------|----------|
| Header mode      | `curl http://proxy -H 'X-Target-URL: https://target/path'`       | no       |
| Host-header mode | `curl http://proxy/path -H 'Host: target'`                       | no       |
| MITM mode        | `curl -x http://proxy --cacert ca.pem https://target/path`       | yes      |

Host-header and Header modes are the simplest — no CA, no cert install,
works from anywhere. MITM mode is useful when you cannot change the
client code (the client already speaks to an HTTP proxy with CONNECT).

## What's new in v0.2.0

- **Streaming everything**. The whole upstream path is a custom
  `http.RoundTripper` feeding `net/http/httputil.ReverseProxy`. Large
  downloads no longer buffer in memory; a 1 GB download uses ~1 MB of
  RSS.
- **HTTP/2 + WebSocket through MITM**. The MITM TLS listener advertises
  `h2` via ALPN and is served by the standard `net/http` server, so
  keep-alive, chunked encoding, trailers, and Upgrade-based protocols
  all work end-to-end.
- **Per-request profile + session isolation** via `X-Fauxbrowser-Profile`
  and `X-Fauxbrowser-Session` headers. Cookies are neutral by default
  (no jar); a jar is created per-session when the session header is set.
- **Context cancellation**. Upstream fetches abort within ~1 s of the
  client disconnecting.
- **Proxy-Authorization Basic** auth and optional **host allow-list**.
- **Graceful shutdown** on SIGINT / SIGTERM with a 15 s drain.
- **CA hygiene**: random 128-bit serial, SKI/AKI, path-length cap,
  397-day leaves, LRU-bounded leaf cache with singleflight.
- **Browser-plausible default headers** (User-Agent, Accept,
  Accept-Language, Accept-Encoding) auto-injected when the caller
  doesn't set them, so sites like `k-ruoka.fi` that check for
  "outdated browser" UA don't reject us at the door.
- **Tests + CI**. `go test -race ./...` covers CA round-trip,
  leaf-cache concurrency, self-host detection, and an end-to-end
  httptest origin exercised through all three modes.

## Quick start

### Native (devenv / Go)

```sh
devenv shell
go build -o fauxbrowser ./cmd/fauxbrowser

# direct (no VPN), ephemeral CA
./fauxbrowser -listen 127.0.0.1:18443

# via gluetun VPN tunnel
./fauxbrowser -listen 127.0.0.1:18443 -upstream http://127.0.0.1:18888

# header mode — no CA trust
curl http://127.0.0.1:18443/ -H 'X-Target-URL: https://www.proshop.dk/'

# Host-header mode — no CA trust
curl -H 'Host: www.proshop.dk' http://127.0.0.1:18443/Grafikkort

# MITM mode — persist a CA so curl can trust it across runs
./fauxbrowser -ca-out ca
curl -x http://127.0.0.1:18443 --cacert ca.pem https://www.proshop.dk/
```

### Per-request overrides

```sh
# fresh session with its own cookie jar, using Firefox 147
curl http://127.0.0.1:18443/ \
  -H 'X-Target-URL: https://httpbin.org/cookies/set?a=1' \
  -H 'X-Fauxbrowser-Profile: firefox147' \
  -H 'X-Fauxbrowser-Session: crawler-A'

# second request reuses the same jar
curl http://127.0.0.1:18443/ \
  -H 'X-Target-URL: https://httpbin.org/cookies' \
  -H 'X-Fauxbrowser-Session: crawler-A'
```

### Nix flake

```sh
nix run github:onnimonni/fauxbrowser -- -listen 127.0.0.1:18443
# or from a checkout
nix build .#fauxbrowser
./result/bin/fauxbrowser --help
```

The flake exposes `packages.default`, `apps.default`, `checks.default`
(runs the full test suite), and a `devShells.default` with Go + curl.

### Docker / OCI

```sh
docker build -t fauxbrowser:latest --build-arg VERSION=$(git rev-parse --short HEAD) .
docker run --rm -p 127.0.0.1:18443:18443 fauxbrowser:latest
```

### docker-compose with gluetun (VPN kill-switch egress)

```sh
cp .env.example .env
# fill .env with YOUR WireGuard values
docker compose up -d
curl http://127.0.0.1:18443/ -H 'X-Target-URL: https://ifconfig.me/ip'
# → VPN exit IP, not your real IP
```

fauxbrowser runs inside gluetun's network namespace so every egress
exits via the VPN. If gluetun's tunnel goes down, gluetun's internal
firewall blocks all fauxbrowser traffic (kill-switch). Never commit
`.env` or `*.conf`; `.gitignore` excludes them.

## Flags and env vars

Every flag has a matching `FAUXBROWSER_<UPPER>` env var (e.g.
`FAUXBROWSER_UPSTREAM`, `FAUXBROWSER_PROFILE`, `FAUXBROWSER_AUTH`).

```
-listen            address to listen on                       (default 127.0.0.1:18443)
-admin-listen      optional /healthz listener                  (empty = disabled)
-upstream          upstream HTTP proxy URL (gluetun etc.)      (empty = direct)
-profile           default browser profile                     (default chrome146)
-ca-cert / -ca-key path to existing CA PEMs                    (auto-generated if missing)
-ca-out            persist auto-generated CA to basename.pem + .key
-target-header     header carrying the target URL              (default X-Target-URL)
-auth              Proxy-Authorization Basic "user:pass"       (required for non-loopback)
-allow-hosts       comma-separated host glob allow-list        (empty = any)
-allow-open        allow non-loopback listen without -auth     (DANGEROUS)
-leaf-cache-max    max cached MITM leaf certs                  (default 1024)
-session-max       max concurrent tls-client sessions          (default 256)
-timeout           per-request upstream timeout seconds        (default 60)
-log-level         debug|info|warn|error                       (default info)
-version           print version and exit
```

### Browser profiles

Default is **chrome146** — the latest Chrome fingerprint shipped in
bogdanfinn/tls-client v1.14.0. Supported aliases:

```
chrome146 | chrome144 | chrome133 | chrome131 | chrome124 | chrome120 | chrome117
firefox147 | firefox135 | firefox133 | firefox123 | firefox117
safari16 | safari_ios_18_5 | safari_ios_16_0 | safari_ios_15_5
opera_90
```

Shortcuts: `chrome` / `latest` → chrome146, `firefox` → firefox147,
`safari` → safari16, `opera` → opera_90.

### Safety defaults

If you bind fauxbrowser to anything other than loopback, it will refuse
to start without either `-auth user:pass` or the explicit `-allow-open`
escape hatch — this prevents accidentally running an open fingerprint-
forging proxy on a public interface. The docker-compose stack sets
`FAUXBROWSER_ALLOW_OPEN=1` because it's bound to the gluetun netns
internally, but you can (and should) also set `FAUXBROWSER_AUTH`.

## Architecture

```
          ┌──────────────────────────── fauxbrowser ────────────────────────────┐
curl ───► │  CONNECT ─┐                                                         │ ───► target
          │           ▼                                                         │
          │       ┌───MITM───┐ in-mem  ┌───── http.Server (h1/h2) ─────┐        │
          │       │ tls.Conn │ ────►   │  handler = ReverseProxy       │  ──┐   │
          │       └──────────┘         └───────────────────────────────┘    │   │
          │                                                                 │   │
          │   X-Target-URL ────────────┐                                    │   │
          │   Host: name ──────────────┼────►  front door rewrites r.URL    │   │
          │   absolute URI ────────────┘       and delegates ...────────────┘   │
          │                                                                     │
          │                      ┌───► Transport.RoundTrip                      │
          │                      │         • pool keyed by (profile, session)   │
          │                      │         • fhttp request w/ r.Context()       │
          │                      │         • streaming body                     │
          │                      │         • hop-by-hop header scrub            │
          │                      │         • browser default headers            │
          │                      └───► bogdanfinn/tls-client (real TLS) ────────┘
          └───────────────────────────────────────────────────────────────────────┘
```

- **One in-memory listener** receives every `*tls.Conn` accepted by the
  MITM CONNECT handlers. One shared `http.Server` (with `http2.ConfigureServer`
  called) handles h1/h2 negotiation, keep-alive, and upgrades.
- **Custom `http.RoundTripper`** converts between `net/http` and
  `bogdanfinn/fhttp` without buffering bodies.
- **Singleflight + LRU** around leaf-cert signing.

## Security notes

- The generated MITM CA can sign a cert for any hostname. **Do not**
  install it in your system trust store. Use `--cacert` on curl or the
  equivalent on whatever client you point at fauxbrowser.
- `ca.key` is written `0600`; `.gitignore` excludes it.
- Enable `-auth` when exposing the listener beyond loopback. Use
  `-allow-hosts` to restrict which upstream hosts may be proxied.
- The docker-compose stack wires fauxbrowser into gluetun's netns; if
  gluetun's tunnel drops, gluetun's firewall blocks fauxbrowser egress.

## Development

```sh
go test -race ./...      # full suite
go build ./cmd/fauxbrowser
nix build .#fauxbrowser  # builds + runs tests via checks.default
```

Layout:

```
cmd/fauxbrowser/main.go          CLI flags, wiring, graceful shutdown
internal/config/                 Config struct + env overlay
internal/ca/                     CA generation, load, LRU leaf cache
internal/proxy/transport.go      tls-client RoundTripper pool
internal/proxy/server.go         ReverseProxy + mode handlers
internal/proxy/mitm.go           CONNECT → in-memory TLS server
internal/proxy/auth.go           Basic auth + host allow-list
internal/proxy/profiles.go       browser profile table
internal/proxy/browser_headers.go UA/Accept defaults per profile
internal/proxy/selfhost.go       self-host detection
internal/proxy/*_test.go         unit + e2e httptest coverage
```

## License

MIT.
