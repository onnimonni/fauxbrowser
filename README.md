# fauxbrowser

Single-binary HTTP proxy for crawlers. Every outbound request:

1. Egresses through an embedded ProtonVPN WireGuard tunnel (userspace
   wireguard-go + gVisor netstack — no `NET_ADMIN`, no `/dev/net/tun`,
   no root).
2. Forges a Chrome TLS fingerprint on the wire via
   [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client).
3. Rotates the exit IP on `429` or WAF-challenge `403`/`503`
   (Cloudflare, DataDome, Akamai, Sucuri). Rotation is **per-host
   blue/green**: the flagged host's traffic is buffered while a new
   tunnel is built in parallel; other hosts keep flowing on the old
   tunnel until it drains.

The listener speaks plaintext **HTTP/1.1 and h2c (HTTP/2 cleartext)
on the same port**, so an Elixir Mint/Finch worker can open one TCP
connection and multiplex requests.

## Quick start

```sh
go build -o fauxbrowser ./cmd/fauxbrowser

# default: any free Proton server, any country
./fauxbrowser -wg-conf /path/to/proton.conf

# lock to specific countries
./fauxbrowser -wg-conf /path/to/proton.conf -vpn-country NL,DE,CH

# lock to a continent
./fauxbrowser -wg-conf /path/to/proton.conf -vpn-continent EU

# with admin listener for /healthz and POST /rotate
./fauxbrowser -wg-conf /path/to/proton.conf \
  -listen 127.0.0.1:18443 \
  -admin-listen 127.0.0.1:18444
```

### Gluetun-compatible env vars

If you don't want to manage a `.conf` file, fauxbrowser can bootstrap
from just the WireGuard private key. The same env-var names that
[gluetun](https://github.com/qdm12/gluetun) uses for ProtonVPN are
honored as aliases:

```sh
WIREGUARD_PRIVATE_KEY="wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=" \
SERVER_COUNTRIES="Netherlands,Germany" \
FREE_ONLY=on \
./fauxbrowser
```

| gluetun env             | fauxbrowser equivalent              |
|-------------------------|-------------------------------------|
| `WIREGUARD_PRIVATE_KEY` | `-wg-private-key` / `FAUXBROWSER_WG_PRIVATE_KEY` |
| `SERVER_COUNTRIES`      | `-vpn-country` / `FAUXBROWSER_VPN_COUNTRIES` |
| `FREE_ONLY=on`          | `-vpn-tier free` / `FAUXBROWSER_VPN_TIER=free` |

`SERVER_COUNTRIES` accepts both ISO-2 codes (`NL,DE`) and country names
(`Netherlands,Germany`). When bootstrapping from the key alone, the
interface address (`10.2.0.2/32`), DNS (`10.2.0.1`), MTU (`1420`), and
`PersistentKeepalive=25` are defaulted to ProtonVPN's published values.

## Client invocation

Three request modes:

```sh
# 1. X-Target-URL header (full feature path: TLS forging, header
#    scrub, rotation, cookie jar)
curl http://127.0.0.1:18443/ -H 'X-Target-URL: https://example.com/path'

# 2. Classic forward-proxy with absolute URI (same feature set)
curl -x http://127.0.0.1:18443 http://example.com/path

# 3. CONNECT tunnel (HTTP_PROXY style for HTTPS targets — Lightpanda,
#    headless browsers, anything that respects HTTP_PROXY env var)
curl -x http://127.0.0.1:18443 https://example.com/path
HTTPS_PROXY=http://127.0.0.1:18443 some-other-tool
```

HTTP/2 cleartext over a single TCP connection:

```sh
curl --http2-prior-knowledge -H 'X-Target-URL: https://example.com/' \
  http://127.0.0.1:18443/
```

### CONNECT tunnel mode caveats

CONNECT is the right mode for routing an HTTP_PROXY-aware client
(Lightpanda, a headless browser, a Python `requests` script with
`HTTPS_PROXY` set) through fauxbrowser purely for **VPN egress**. But:

- **TLS fingerprint forging is bypassed.** The client speaks its own
  TLS handshake to the target through the tunnel; fauxbrowser sees
  only encrypted bytes. If the target is behind a TLS-fingerprint-
  aware WAF (Cloudflare IUAM, Akamai Bot Manager, DataDome) you will
  fail. For those targets, use X-Target-URL mode.
- **Rotation visibility is bypassed.** fauxbrowser cannot see HTTP
  status codes inside the encrypted stream, so the 429/403/503
  heuristic does NOT fire on CONNECT traffic. You can still rotate
  manually via `POST /rotate`.
- **Header scrub is bypassed.** `X-Forwarded-For`, `Via`, etc. that
  the client sets are inside the encrypted stream — fauxbrowser
  never sees them. Make sure your client doesn't set them.
- **Per-host quarantine still applies at dial time.** If host A was
  recently quarantined by a 429 in X-Target-URL mode, a CONNECT dial
  to A blocks on the gate.
- **HTTP/1.1 only.** h2c CONNECT is not supported (h2 strips
  Hijacker support).
- **Auth.** Set `Proxy-Authorization: Bearer <token>` (the
  forward-proxy convention) or `Authorization: Bearer <token>`
  (also accepted). Failure on CONNECT returns 407 Proxy
  Authentication Required.

### From Elixir (Mint / Finch)

```elixir
{:ok, conn} = Mint.HTTP.connect(:http, "127.0.0.1", 18443, protocols: [:http2])
{:ok, conn, ref} =
  Mint.HTTP.request(conn, "GET", "/", [
    {"x-target-url", "https://example.com/"}
  ], nil)
```

## Install on NixOS

The flake ships `nixosModules.default` + an overlay:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fauxbrowser = {
      url = "github:onnimonni/fauxbrowser";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fauxbrowser, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        fauxbrowser.nixosModules.default
        ({ ... }: {
          services.fauxbrowser = {
            enable = true;
            wgConfFile = "/run/secrets/proton-vpn.conf";  # sops-nix / agenix
            vpnCountries = [ "NL" "DE" ];
          };
        })
      ];
    };
  };
}
```

The systemd unit is hardened (`DynamicUser=true`, `ProtectSystem=strict`,
empty `CapabilityBoundingSet`, `MemoryDenyWriteExecute=true`,
`LoadCredential` for secret tokens).

## Flags

```
-listen                h2c+h1 listen address                       (default 127.0.0.1:18443)
-admin-listen          optional /healthz + /rotate listener        (empty = disabled)
-wg-conf               path to a wg-quick .conf (REQUIRED)
-vpn-tier              free (default) | paid | all
-vpn-country           comma-separated ISO-2 country allow-list
-vpn-continent         comma-separated continent allow-list        (EU,NA,AS,OC,SA,AF)
-profile               browser profile                             (default chrome146)
-auth-token            bearer token on the proxy listener          (MANDATORY for non-loopback)
-admin-token           bearer token on the admin listener          (MANDATORY for non-loopback)
-timeout               per-request upstream timeout, seconds       (default 60)
-cooldown              per-server taint cooldown, seconds          (default 900)
-handshake-wait        max WG handshake wait per rotation attempt  (default 6s)
-host-debounce         per-host rotation debounce window           (default 5m)
-rotation-min-interval global min between any two rotations        (default 2s)
-retire-max-age        force-close retired tunnels past this age   (default 2m)
-reaper-interval       how often the reaper scans                  (default 5s)
-log-level             debug|info|warn|error                       (default info)
```

Every flag also reads from `FAUXBROWSER_<UPPER>` env vars, e.g.
`FAUXBROWSER_AUTH_TOKEN`, `FAUXBROWSER_PROFILE`.

### Bearer auth

- Default deployment is on `127.0.0.1`, no auth required.
- Binding either listener to a non-loopback address refuses to start
  without a corresponding token set. Requests must send
  `Authorization: Bearer <token>`; comparison is constant-time.

### Browser profiles

Supported: `chrome146` (default), `chrome144`, `chrome133`, `chrome131`,
`latest` (= chrome146). Each entry pins the TLS fingerprint, the
User-Agent, and the `sec-ch-ua` bundle together — a CI test asserts
they all agree on the Chrome major version.

## Rotation heuristics

| Status | Rotate? |
|--------|---------|
| `429`  | Always |
| `403`  | Only with `cf-mitigated`, `server: cloudflare`, `x-datadome`, `x-iinfo`/`server: akamai`, `x-sucuri-id` |
| `503`  | Only with the same WAF markers |
| other  | Never |

Plain `401` / `403` (auth, geo-block) do **not** burn an IP.

### Blue/green per-host rotation

When a rotation is triggered:

1. The flagged host is quarantined — new requests to it wait on a
   gate. Other hosts keep flowing on the current tunnel.
2. A new tunnel is built in parallel (pick peer → handshake →
   liveness probe). Once live, it becomes the new current.
3. The quarantine lifts; buffered requests drain through the new
   tunnel. All subsequent requests (to any host) also use it.
4. The old tunnel is marked retiring. The reaper closes it once its
   in-flight counter reaches zero, or after `-retire-max-age` as a
   backstop.
5. If the same host is hit again within `-host-debounce`, fauxbrowser
   refuses to rotate again — the upstream response passes through
   unchanged. This prevents concurrent bursts of 429s from burning
   the Proton pool.

## Cookie policy

- Internal cookie jar persists `Set-Cookie` responses across requests
  to the same host.
- On rotation, the jar is cleared so nothing bound to the old exit IP
  leaks.
- Caller-supplied `Cookie:` headers on incoming requests are always
  forwarded verbatim. Those are "the client's cookies" — fauxbrowser
  only manages its own jar.

## Architecture

```
┌────────── fauxbrowser ──────────────────────────────────────────┐
│                                                                 │
│ Elixir ──► h2c listener ──► NewHandler ──► ReverseProxy ──► Transport
│            (plaintext,                                     │
│             HTTP/1.1 +                                     ▼
│             h2 multiplexed)                         tls-client (chrome146)
│                                                           │
│                                                           ▼
│                                                  rotator.Dialer  ◄── RotateIfTriggered(429/403/503)
│                                                           │
│                                                           ▼
│                                       wgtunnel (userspace wg + netstack)
│                                                           │
└───────────────────────────────────────────────────────────┼──── Proton WG peer
                                                            │
                                                            ▼
                                                          target
```

## Tests

```sh
go test -race ./...
```

Coverage:
- `internal/proton`: catalog + pool, country/continent/tier filtering.
- `internal/rotator`: heuristic matrix + blue/green state machine
  (happy path, host quarantine, debounce, drain, concurrent burst).
- `internal/wgtunnel`: wg-quick parsing, `WithPeer` clone.
- `internal/proxy`: h2c multiplexing, header scrub, bearer auth,
  profile coherence invariant.

## Credits

fauxbrowser stands on the shoulders of two excellent upstream
projects, without which it wouldn't exist:

- **[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)** —
  the patched uTLS fork that drives every outbound TLS handshake.
  It ships the Chrome, Firefox, and Safari TLS profiles that make
  fingerprint forging actually work on modern WAFs.
- **[qdm12/gluetun](https://github.com/qdm12/gluetun)** — the
  reference VPN sidecar whose approach to WireGuard-through-gVisor,
  kill-switch semantics, and provider discovery shaped the rotator
  design here. Gluetun is still the right choice if you want a
  general-purpose multi-provider VPN container; fauxbrowser is the
  right choice if you want one binary that also forges TLS
  fingerprints and rotates exits on rate-limits.

## License

MIT.
