# fauxbrowser

Tiny HTTP proxy that forges browser TLS fingerprints for curl / any HTTP client.

Internally uses [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)
(which uses a patched utls) so the outgoing TLS handshake matches a real
Chrome/Firefox/Safari. Optionally chains through an upstream HTTP proxy such
as [qdm12/gluetun](https://github.com/qdm12/gluetun) so the whole thing
egresses via WireGuard/OpenVPN without leaking your real IP.

Two ways to talk to it:

| Mode             | Client invocation                                                | CA trust required? |
|------------------|------------------------------------------------------------------|--------------------|
| Header mode      | `curl http://proxy -H 'X-Target-URL: https://target/path'`       | No                 |
| Host-header mode | `curl http://proxy/path -H 'Host: target'`                       | No                 |
| MITM mode        | `curl -x http://proxy --cacert ca.pem https://target/path`       | Yes                |

Host-header mode is especially handy because most HTTP clients let you override
the `Host` header directly, so URLs can stay unchanged:
`curl -H 'Host: www.proshop.dk' http://127.0.0.1:18443/Grafikkort`.
Scheme defaults to `https`; override with `X-Target-Scheme: http` if needed.

Header mode is the simplest: no CA, no cert installation, works from anywhere
that can make an HTTP request. MITM mode is useful when you cannot change the
client code / URLs (the client already speaks to an HTTP proxy).

## Quick start

### Native (devenv / Go)

```sh
devenv shell
go build -o fauxbrowser .

# direct, no VPN, auto-generated ephemeral CA
./fauxbrowser -listen 127.0.0.1:18443

# chained through a gluetun HTTP proxy
./fauxbrowser -listen 127.0.0.1:18443 -upstream http://127.0.0.1:18888

# header mode (no CA needed)
curl http://127.0.0.1:18443/ -H 'X-Target-URL: https://www.proshop.dk/'

# MITM mode (need the CA cert curl will trust)
./fauxbrowser -ca-out ca                       # writes ca.pem + ca.key
curl -x http://127.0.0.1:18443 --cacert ca.pem https://www.proshop.dk/
```

### Nix flake

```sh
nix run github:onnimonni/fauxbrowser -- -listen 127.0.0.1:18443
# or from a checkout
nix build .#fauxbrowser
./result/bin/fauxbrowser --help
```

The flake also exposes `packages.default`, `apps.default`, and a `devShells.default`
with Go + curl.

### Docker / OCI

```sh
docker build -t fauxbrowser:latest .
docker run --rm -p 127.0.0.1:18443:18443 fauxbrowser:latest
```

### docker-compose with gluetun (VPN kill-switch egress)

`docker-compose.yml` in this repo runs fauxbrowser inside gluetun's network
namespace: all fauxbrowser egress exits via the VPN, and the host only sees
port 18443 through gluetun.

```sh
cp .env.example .env
# fill .env with YOUR wireguard values (extracted from your own .conf)
docker compose up -d
curl http://127.0.0.1:18443/ -H 'X-Target-URL: https://ifconfig.me/ip'
# → should print the VPN exit IP, not your real IP
```

**Never commit `.env` or `*.conf` files.** `.gitignore` already excludes them.

## Flags

```
-listen          address to listen on                   (default 127.0.0.1:18443)
-upstream        upstream HTTP proxy URL                (empty = direct)
-profile         browser profile                        (default chrome146)
                 options: chrome146 | chrome144 | chrome133 | chrome120
                          | firefox123 | safari16
-ca-cert         path to existing CA cert PEM           (for MITM mode)
-ca-key          path to existing CA private key PEM    (for MITM mode)
-ca-out          basename; writes <name>.pem + <name>.key when auto-generating
-target-header   header name for header mode            (default X-Target-URL)
-timeout         per-request upstream timeout, seconds  (default 60)
```

If neither `-ca-cert` nor `-ca-key` is given, a fresh CA is generated in
memory on every start. Pass `-ca-out ca` once to persist it and then reuse
it with `-ca-cert ca.pem -ca-key ca.key` on subsequent runs.

## Browser profile

Default is **chrome146** — the latest Chrome fingerprint shipped in
bogdanfinn/tls-client v1.14.0. Switch with `-profile chrome144` etc. if you
need an older one for A/B testing.

## How header mode works

```
┌──────┐  GET /  host=proxy  ┌────────────┐  TLS (chrome146)  ┌──────────┐
│ curl ├────────────────────→│  fauxbrowser ├──────────────────→│  target  │
└──────┘  X-Target-URL: ...  └────────────┘   via -upstream   └──────────┘
```

fauxbrowser reads the URL from `X-Target-URL`, calls it through tls-client,
and streams the response back as-is. Response headers are forwarded except
the hop-by-hop ones (`Transfer-Encoding`, `Content-Length`, `Content-Encoding`,
`Connection`).

## How MITM mode works

```
┌──────┐  CONNECT host:443  ┌────────────┐
│ curl ├───────────────────→│  fauxbrowser │
│      │←── 200 ────────────│            │
│      │== TLS (fake CA) ==→│            │  tlsConn
│      │  GET / host: host  │            ├──── tls-client ───→ target
└──────┘                    └────────────┘   (chrome146)
```

1. curl opens CONNECT. fauxbrowser hijacks the socket and replies 200.
2. fauxbrowser mints a leaf cert for `host` signed by its own CA, TLS-handshakes
   with curl. curl must have the CA cert in its trust set (`--cacert`).
3. fauxbrowser reads the decrypted request, re-fetches it via tls-client with
   the real browser handshake, and writes the response back over the
   curl-side TLS connection.

Leaf certs are cached per host so repeated requests don't re-mint.

## Security notes

- The generated CA can sign a cert for any hostname. **Do not** install it
  into your system trust store. Use `--cacert` on curl or the equivalent on
  whatever client you point at fauxbrowser.
- Keep `ca.key` file-permissions tight (`0600`) and out of version control.
  `.gitignore` already excludes `ca.pem` / `ca.key`.
- The included `docker-compose.yml` wires fauxbrowser into gluetun's netns;
  if gluetun's tunnel goes down, gluetun's internal firewall blocks all
  fauxbrowser egress (kill-switch behavior). Verify before you trust it.

## License

MIT.
