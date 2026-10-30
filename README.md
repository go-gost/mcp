# gost-mcp

`gost-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server that gives an agent three network primitives: two through egress profiles you configure, and one through a wisp relay.

1. **One HTTP(S) request through a chosen egress** — `gost-run`.
2. **A staged connectivity diagnosis through a chosen egress** — `gost-trace`.
3. **A temporary public URL for a loopback HTTP service** — `gost-wisp` / `gost-unwisp`.

It is a single binary that speaks MCP over stdio. It needs no running gost instance, no sidecar, no database, and no network listener of its own.

## What it is

- **Explicit egress.** Every `gost-run` and `gost-trace` call names an egress profile from a local file. An omitted or unknown profile is an error; there is no silent fallback to a direct connection. (`gost-wisp` and `gost-unwisp` use the configured relay, not an egress profile.)
- **One-shot.** Each call is self-contained and returns a complete result or a classified failure such as `stage=connect, code=timeout`. Nothing is inferred from previous calls. The only state that outlives a call is a wisp lease, addressed by an explicit handle.
- **Local.** Egress profiles are read once at startup from `gost-mcp.yml`. There is no remote profile distribution and no hot reload.
- **Small surface.** Four tools and two resources. `gost-mcp://egress` exposes profile names and descriptions only; node addresses appear there only when you opt in with `--expose-topology`. That filter is about the resource, not about every string: a failure message can quote the address of the node that failed (for example `dial tcp 10.0.0.2:8080: i/o timeout`), because `failure.message` comes straight from the dial path.

## What it is not

- **Not a gost control plane.** It does not read, write, reload, or observe a gost service's configuration, logs, metrics, or traffic records. It does not talk to gost's API.
- **Not a proxy server.** It does not listen for SOCKS or HTTP clients and cannot be used to proxy another process. In v0 it has no network listener at all; MCP runs over stdio.
- **Not a sandbox.** Tool calls run with your user's network identity. See [Security](#security).
- **Not a tunnel manager for arbitrary services.** `gost-wisp` publishes HTTP services on loopback only by default. It does not expose TCP/UDP, and a lease dies with the process.
- **Not a traceroute.** `gost-trace` reports cumulative chain prefixes (`direct`, `hop 0`, `hop 0+1`, ...). Per-hop timing inside a hop group is not observable.

## Requirements

- Go 1.26.3 or newer to build from source; the Docker image uses Go 1.27.
- Any MCP client that supports local (stdio) servers: Claude Code, OpenCode, Codex, or another MCP host.

## Install

From source:

```sh
git clone https://github.com/go-gost/mcp
cd mcp
make build
install -m 0755 gost-mcp /usr/local/bin/gost-mcp
gost-mcp --version
```

With Docker (the image reads `/etc/gost-mcp/gost-mcp.yml` by default):

```sh
docker build -t gost-mcp .

docker run --rm -i \
  -v "$PWD/gost-mcp.yml:/etc/gost-mcp/gost-mcp.yml:ro" \
  -e JP_USER -e JP_PASS \
  gost-mcp
```

`-i` is required: MCP uses stdin/stdout. Do not pass `-t`; a TTY corrupts the protocol stream. The image ships `gost-mcp.example.yml` as `/etc/gost-mcp/gost-mcp.yml` (a `direct` profile only), so mount your own file over it for real egress profiles.

With npm (no Go toolchain or config file needed):

```sh
npx -y @go-gost/mcp
```

See [docs/distribution.md](docs/distribution.md) for the release pipeline, the
Claude Code / Codex / OpenCode snippets, and the npm and MCP Registry publishing
steps.

## Tools

| Tool | What it does | Annotations |
|------|--------------|-------------|
| `gost-run` | Sends one HTTP(S) request through an egress profile. | open-world, non-destructive |
| `gost-trace` | Diagnoses DNS/TCP/TLS/HTTP/UDP reachability through an egress profile. | read-only, open-world |
| `gost-wisp` | Publishes a loopback HTTP service at a public wisp URL for a bounded lease. | open-world, non-destructive |
| `gost-unwisp` | Releases a lease early. Idempotent. | idempotent, non-destructive |

`gost-run` and `gost-trace` require `egress` and treat it as a **profile name**, never a URI. A non-2xx HTTP status from `gost-run` is a successful call. Transport failures come back as `ok=false` with a `failure` object; they are not MCP protocol errors.

### `gost-run`

```json
{
  "tool": "gost-run",
  "arguments": {
    "egress": "jp",
    "url": "https://ifconfig.co/json",
    "timeout_ms": 15000
  }
}
```

Abridged output:

```json
{
  "ok": true,
  "status": 200,
  "status_text": "OK",
  "final_url": "https://ifconfig.co/json",
  "redirects": [],
  "headers": {"content-type": "application/json"},
  "body": "{\"ip\":\"203.0.113.7\", ...}",
  "body_encoding": "utf8",
  "bytes": 118,
  "truncated": false,
  "sha256": "…",
  "timings": {"connect_ms": 214, "tls_ms": 96, "ttfb_ms": 341, "total_ms": 402},
  "egress": {"name": "jp"},
  "failure": null
}
```

Arguments: `egress` and `url` are required. Optional: `method` (default `GET`), `headers` (literal values only), `body`, `body_encoding` (`utf8` or `base64`), `timeout_ms` (default 30000, max 120000), `max_bytes` (default 1 MiB, max 8 MiB), `follow_redirects` (default true, max 5).

Notes:

- Response bodies are read up to `max_bytes + 1` so truncation is reported.
- Text-like content is returned as UTF-8; anything else as base64.
- Only an allowlist of response headers is echoed to keep output small: `content-type`, `content-length`, `server`, `location`, `content-encoding`, `retry-after`, and a capped set of `x-*`.
- There is no separate DNS timing: through SOCKS5 or HTTP CONNECT the exit resolves the name, so `connect_ms` covers it. A local lookup would be a second, hidden egress.

### `gost-trace`

```json
{
  "tool": "gost-trace",
  "arguments": {
    "egress": "corp",
    "target": "example.com:443"
  }
}
```

Abridged output:

```json
{
  "ok": false,
  "target": "example.com:443",
  "mode": "tcp",
  "egress": {"name": "corp"},
  "stages": [
    {"name": "resolve", "ok": true, "ms": 2, "detail": {"addrs": ["203.0.113.10"]}},
    {"name": "connect", "ok": false, "ms": 3100, "error": {"stage": "connect", "code": "timeout", "message": "dial tcp 10.0.0.2:8080: i/o timeout", "retryable": true}}
  ],
  "attribution": {"path": ["hop-0", "hop-1"], "stage": "connect", "code": "timeout"},
  "prefixes": [
    {"path": ["direct"], "ok": true, "ms": 35, "served_by": []},
    {"path": ["hop-0"], "ok": true, "ms": 120, "served_by": ["a"]},
    {"path": ["hop-0", "hop-1"], "ok": false, "ms": 3100, "served_by": ["b"], "stage": "connect", "code": "timeout"}
  ],
  "identity": {},
  "failure": {"stage": "connect", "code": "timeout", "message": "dial tcp 10.0.0.2:8080: i/o timeout", "retryable": true}
}
```

Arguments: `egress` and `target` are required. `target` may be `host:port`, an `http(s)://` URL, `udp://host:port`, `tls://host:port`, or `dns://name`. Optional: `mode` (`auto`, `tcp`, `udp`, `dns`, `tls`, `http`), `resolver` (for `mode=dns`), `prefix` (default true), `timeout_ms` (default 10000, max 60000), `payload` (base64), `expect` (substring), `identity` (default false).

Notes:

- `mode=auto` infers `http` for `http(s)://` URLs, `tcp` for a bare `host:port`, `udp` for `udp://`, `dns` for `dns://`, and `tls` for `tls://`. A bare `example.com:443` is a TCP trace, not a TLS handshake.
- The `resolve` stage is local and informational. With SOCKS5/HTTP CONNECT the exit resolves the name, so a local DNS failure does not prove the chain fails.
- `mode=dns` sends an explicit query **through the egress** to `resolver` (default: the first nameserver in `/etc/resolv.conf`).
- Prefix probing connects only and stops at the first failure. The full chain then runs the complete stage test. With a multi-node hop, the probe and the final attempt may use different nodes, so attribution is best-effort and each prefix reports `served_by` (node names, never addresses).
- The **first prefix is a direct baseline**: `gost-trace` dials the target from *this host*, without the selected egress, and reports it as `path: ["direct"]`. That baseline is real traffic leaving from here even when a proxy profile is selected. It is bounded to min(2s, 20% of the call budget), its failure does not stop the hop probes, and a connect failure is attributed to the first failing *hop* prefix (never to `direct` unless it is the only probe result). Pass `prefix: false` when even that single direct connection is not acceptable.
- `timeout_ms` is a budget for the whole call. A timeout returns the prefixes that completed plus `ok=false`.
- An empty route is `code=no_route`, never a direct dial.
- `identity` makes one extra request through the full chain to `gost-trace.identity_url` (HTTPS by default) and reports `{ip, family, country, asn, org}` when the endpoint provides them.

### `gost-wisp`

```json
{
  "tool": "gost-wisp",
  "arguments": {
    "local": "127.0.0.1:3000",
    "ttl_s": 600,
    "label": "preview",
    "verify": true
  }
}
```

```json
{
  "ok": true,
  "url": "https://134c714b65d54a4f.gost.run",
  "handle": "7f3c2a1b9d40a1b2",
  "local": "127.0.0.1:3000",
  "expires_at": "2026-10-29T12:15:00Z",
  "state": "active",
  "verify": {"checked": true, "status": 200}
}
```

Arguments: `local` is required and must be a `host:port` that resolves entirely inside `gost-wisp.allow`. The host may be an IP literal or a DNS name such as `localhost`; it is resolved once, every address must be allowed, and the first IPv4 address (else the first IPv6) is pinned. Optional: `ttl_s` (default 900, capped by `gost-wisp.max_ttl`), `label` (free text for logs, capped at 128 bytes; never part of the URL), `verify` (default true, one GET through the public URL).

Notes:

- The URL is `https://<relay-label>.<gost-wisp.domain>`. The relay is configuration, never a tool argument.
- The handle is 16 lowercase hex characters, opaque, and unrelated to the public label.
- The relay may re-bind a tunnel and issue a new label. Read `gost-mcp://leases` for the current URL instead of reusing a stale one. States are `active`, `rebound`, `expired`, and `dead` (the relay service stopped unexpectedly; its slot is free and the record remains for reporting).
- `verify` only proves the tunnel at creation time; any HTTP status, including 401 or 404, means the tunnel works. It does not follow a redirect and ignores environment proxies.
- Leases are in memory. Process exit closes them all.

### `gost-unwisp`

```json
{"tool": "gost-unwisp", "arguments": {"handle": "7f3c2a1b9d40a1b2"}}
```

```json
{"ok": true, "released": true, "url": "https://134c714b65d54a4f.gost.run"}
```

An unknown, expired, or dead handle returns `released=false` rather than an error.

### Resources

- `gost-mcp://egress` — configured profiles as `{name, description}`. Node addresses appear only with `--expose-topology`, and credentials are stripped.
- `gost-mcp://leases` — leases as `{handle, url, local, label, state, expires_at}`, including expired and dead records retained for reporting. Read this after a re-bind.

## Configuration

`gost-mcp` looks for its file in this order:

1. `--config PATH`
2. `./gost-mcp.yml`
3. `~/.gost-mcp/gost-mcp.yml`
4. `/etc/gost-mcp/gost-mcp.yml`

The file is read once. Changing a profile requires a restart.

A complete example:

```yaml
# Egress profiles. The schema is gost's chain/hop schema; `chain:` is the -F sugar.
egress:
  - name: direct
    description: "Host direct, no proxy"
    chain: []

  - name: jp
    description: "Tokyo residential exit (SOCKS5)"
    chain:
      - "socks5://${JP_USER}:${JP_PASS}@tokyo.example.com:1080"

  - name: corp
    description: "Corp exit: HTTP proxy, then internal SOCKS5"
    hops:
      - name: hop-0
        selector: { strategy: round }
        nodes:
          - { name: a, addr: "10.0.0.1:8080", connector: { type: http } }
          - { name: b, addr: "10.0.0.2:8080", connector: { type: http } }
      - name: hop-1
        nodes:
          - { name: c, addr: "10.0.1.5:1080", connector: { type: socks5 } }

  - name: wifi
    description: "Force wlan0, to compare with the cellular exit"
    chain:
      - "socks5://192.168.1.10:1080?interface=wlan0"

gost-run:
  timeout: 30s
  max_bytes: 1MiB

gost-trace:
  timeout: 10s
  identity_url: "https://ifconfig.co/json"

gost-wisp:
  relay: "tunnel+wss://wisper.gost.run:443"
  domain: "gost.run"
  max_ttl: 1h
  max_leases: 4
  # Loopback only by default. Widening is configuration-only, never a tool argument.
  allow: ["127.0.0.0/8", "::1/128"]

log:
  level: info          # gost-mcp's own logs; stdout is the MCP channel
```

`gost-mcp.example.yml` in this repository is the same shape with commented credentials; the Docker image installs it as `/etc/gost-mcp/gost-mcp.yml`.

### Profile rules

- A profile needs a unique `name` matching `[a-z0-9_-]{1,32}` and a non-blank `description`.
- Set exactly one of `chain` or `hops`.
  - `chain` is a list of gost `-F` URIs; **each entry is one hop**. A URI scheme must be a connector or dialer this build registered (`http`, `https`, `socks5`, `ss`, `tunnel+wss`, ...); an unknown scheme such as `grpc://` or an alias such as `socks5h://` is rejected instead of falling back to HTTP.
  - `hops` is the full hop schema, for a pool of nodes in one hop. An explicit node's `addr` is `host:port` with no `://`; the protocol lives in `connector: { type: http|socks5|... }`. A missing connector type means HTTP. `direct` and `virtual` connectors are rejected because they skip the egress.
  - `chain: []` is the explicit direct profile. There is no implicit direct egress.
- Hop- and node-level `bypass`, `bypasses`, `matcher`, and `filter` are rejected. They can make gost skip a hop and eventually dial direct, which would turn a configured egress into a hidden bypass. Use a separate `direct` profile.
- `node.probe` is rejected: an egress profile must not generate active probe traffic unrelated to a tool call.
- Dynamic node sources (`file`, `redis`, `http`, `plugin`), `reload`, and named `resolver`/`hosts` components are rejected. Nodes must be static for the process lifetime.
- File-level `services`, `authers`, `resolvers`, `hosts`, `plugins`, and `sd` are rejected rather than silently ignored.
- Chain query parameters `bypass`, `bypasses`, `matcher`, `filter`, `resolver`, `hosts`, and `sd` are rejected.

### Settings and defaults

| Key | Default | Notes |
|-----|---------|-------|
| `gost-run.timeout` | `30s` | Per-call default; the tool can pass `timeout_ms` up to 120000. |
| `gost-run.max_bytes` | `1MiB` | Per-call default; the tool can pass `max_bytes` up to 8 MiB. |
| `gost-trace.timeout` | `10s` | Budget for the whole trace; the tool can pass up to 60000 ms. |
| `gost-trace.identity_url` | `https://ifconfig.co/json` | Used only when a call sets `identity: true`. |
| `gost-wisp.relay` | `tunnel+wss://wisper.gost.run:443` | Configuration-only; not a tool argument. |
| `gost-wisp.domain` | `gost.run` | Public suffix used to build the URL. |
| `gost-wisp.max_ttl` | `1h` | Range `1s..24h`; a larger `ttl_s` is clamped. |
| `gost-wisp.max_leases` | `4` | Range `1..64`; concurrent live leases. |
| `gost-wisp.allow` | `127.0.0.0/8`, `::1/128` | IPs or CIDR prefixes. A target must resolve entirely inside the list. |
| `log.level` | `info` | `debug`, `info`, `warn`, or `error`; controls gost-mcp's own logger. |
| `log.file` | empty | Append gost-mcp logs to this file; empty writes to stderr. stdout is reserved for MCP frames. Embedded gost components keep their own logger and do not necessarily write here. |

Durations accept Go syntax (`30s`, `1h`) or a bare number of seconds. Sizes accept a byte count or `1MiB`-style strings.

## `${ENV}` expansion

`${NAME}` references in **scalar string values** are expanded after YAML parsing. Only the braced form is expanded, so a bare `$` in a password survives.

- An unset variable is a **startup error**, never an empty string. A missing credential cannot silently become an anonymous connection.
- Keys and comments are not values, so `${...}` in them is left untouched and never fails startup.
- Substitution happens on the parsed value, so a password containing `"`, `#`, or `:` cannot break the YAML structure. URL metacharacters still need percent-encoding inside a `chain:` URI.
- Put credentials in the MCP client's `environment`/`env` block and reference them here. Do not commit them to the YAML.

## Validate the configuration

```sh
gost-mcp --config /etc/gost-mcp/gost-mcp.yml --check
```

```
direct  Host direct, no proxy            0 hops  0 nodes
jp      Tokyo residential exit (SOCKS5)  1 hop   1 node
```

`--check` parses, expands, validates, and **builds** every profile, then prints name, description, hop count, and node count — never addresses or credentials. Building is what catches an unregistered chain scheme or a bad node address, not just a syntax error. It exits `0` when the file is valid and `1` when it is not. It also warns when the file is group- or world-readable, because it may contain credentials:

```
gost-mcp: warning: /etc/gost-mcp/gost-mcp.yml is accessible by group or others (0644); it may contain credentials, use 0600
```

`--skip-invalid` drops profiles that fail validation (with a warning) instead of failing startup. File-level errors are never skipped.

Other flags:

| Flag | Meaning |
|------|---------|
| `--config PATH` | Configuration file. |
| `--check` | Validate, print profiles, exit. |
| `--skip-invalid` | Skip bad profiles at startup. |
| `--expose-topology` | Include node addresses in `gost-mcp://egress`. |
| `--version` | Print the version and exit. |

## MCP client configuration

A server entry needs a command, the config path, and the environment variables that `${...}` references need:

```json
{
  "command": "/usr/local/bin/gost-mcp",
  "args": ["--config", "/etc/gost-mcp/gost-mcp.yml"],
  "env": {
    "JP_USER": "alice",
    "JP_PASS": "s3cret"
  }
}
```

Per-host examples, with the exact snippet and worked prompts:

- [Claude Code](examples/claude-code.md)
- [OpenCode](examples/opencode.md)
- [Codex](examples/codex.md)

Keep the config file out of version control (`.gitignore` already ignores `gost-mcp.yml` and `.gost-mcp/`).

## Security

Read this before pointing the server at anything real.

- **The server runs with your network identity, not in a sandbox.** A tool call can reach whatever the process can reach through the configured proxies. The egress file bounds *how* traffic leaves and which profiles exist; it is not a security boundary against a malicious model or prompt injection. Run it as a dedicated unprivileged user if that matters.
- **A published URL is public and unauthenticated.** Anyone who learns a `gost-wisp` URL can reach the local service until the lease is released or expires. The local service must authenticate its own users. Do not publish an admin UI or an unauthenticated internal API.
- **Publishing is loopback-only by default.** `gost-wisp.allow` defaults to `127.0.0.0/8` and `::1/128`. Widening it is a configuration decision; there is no tool argument for it. The relay address is also configuration-only, so a model cannot point a tunnel at an arbitrary relay.
- **There is no `env:` header indirection.** `gost-run.headers` values are literal. A secret placed in a header is visible to the model and in the request. This is deliberate: header-to-server-secret indirection would let a prompt-injected model exfiltrate a credential to an arbitrary host.
- **Credentials belong in the MCP client's environment, not the YAML.** Reference them as `${JP_PASS}`. If the file does contain credentials, `chmod 0600` it; `--check` and startup warn when it is group- or world-readable.
- **No hidden direct egress in the requested path.** `egress` is required, an unknown name is an error, and profiles cannot use `bypass`/`matcher`/`filter` to skip a hop: the requested egress never falls back to a direct dial. One connection is direct on purpose — the [`gost-trace` prefix baseline](#gost-trace), which always dials from this host. Pass `prefix: false` if that baseline is not acceptable.
- **No network listener in v0.** MCP uses stdio, so there is no port to authenticate. stdout carries protocol frames; gost-mcp's own logs and warnings go to stderr or `log.file`.
- **Leases are logged and bounded.** A publication logs label, target, URL, handle, and expiry; a release logs the handle, URL, and `released` flag. Neither includes credentials or node addresses. TTL, lease count, and target allow-list are enforced.

## Build and test

```sh
make build     # ./gost-mcp with the version from git describe
make test      # go test ./...
make race      # CGO_ENABLED=1 go test -race ./...
make check     # build, then validate internal/config/testdata/egress.yml
make lint      # gofmt check and go vet
```

Without `make`:

```sh
CGO_ENABLED=0 go build -trimpath -o gost-mcp ./cmd/gost-mcp
go test ./...
CGO_ENABLED=1 go test -race ./...
./gost-mcp --version
./gost-mcp --config internal/config/testdata/egress.yml --check
```

The version comes from `-ldflags "-X main.version=v0.1.0"`; a plain `go build` reports `dev`. Release builds are produced by [goreleaser](https://goreleaser.com) from `.goreleaser.yaml` (linux/darwin/windows, amd64/arm64, `CGO_ENABLED=0`, no UPX). The Docker image is built from the `Dockerfile`.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `config: no configuration file found` | No `--config` and no file in the default search paths. |
| `config: undefined environment variable(s): X` | The MCP client did not pass `X` in its `env` block. |
| `unknown egress "x"; available profiles: ...` | The profile is missing or the server was not restarted after editing. |
| `ok=false`, `stage=connect`, `code=no_route` | A hop selected no node; the chain was rejected instead of dialing direct. |
| `ok=false`, `stage=proxy_auth`, `code=proxy_auth_failed` | Wrong proxy credentials; check `${...}` expansion. |
| `gost-wisp: target not allowed` | The target resolved outside `gost-wisp.allow`. |
| `gost-wisp: max leases reached` | Release a lease with `gost-unwisp` or raise `max_leases`. |
| A published URL stops working | The lease expired, the relay service died (`state=dead`), the process restarted, or the relay re-bound it; read `gost-mcp://leases`. |

## License

MIT. See [LICENSE](LICENSE).
