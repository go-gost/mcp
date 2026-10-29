# gost-mcp — Design

- Status: draft, awaiting approval
- Date: 2026-10-29
- Repository: `github.com/go-gost/mcp` (new)
- Binary: `gost-mcp`

## 1. Intent

Agents need three network primitives that a sandboxed shell usually cannot provide portably, and that generic "web fetch" tools do not cover:

1. **Reach a target through a chosen egress** — a proxy chain the operator preconfigured, not whatever the host happens to route.
2. **Know where a connection dies** — DNS, TCP, TLS, HTTP, or policy — with the first failing chain prefix named.
3. **Publish a local HTTP service at a public URL for a short while** — via the existing `wisper.gost.run` relay.

gost already implements all the machinery. This project exposes exactly those three primitives to MCP clients, one call at a time, and nothing else.

It is **not** a gost control plane: it does not read, write, reload, or observe a gost service's configuration, logs, or metrics.

## 2. Positioning

- One-shot: every call is self-contained and returns a complete result or a classified failure.
- No daemon required: no running gost instance, no sidecar, no database.
- No remote profile distribution: egress profiles are a local file read at startup.
- No hidden egress: an egress profile is always explicit.

"Stateless" describes the model's view and the MCP transport. The one resource that outlives a call — a public tunnel — is represented by an explicit handle (see §7.3), which the 2026-07-28 MCP spec recommends over transport session state.

## 3. Goals

| ID | Goal |
|----|------|
| G1 | `gost_run`: send one HTTP(S) request through a named egress; return status, headers, body, per-stage timings, and a classified failure. |
| G2 | `gost_trace`: diagnose DNS/TCP/TLS/HTTP/UDP reachability through an egress, attribute the failure to the first failing chain prefix, optionally report the public egress identity. |
| G3 | `gost_wisp`: publish a loopback HTTP service at `https://<label>.gost.run` for a bounded TTL; `gost_unwisp` releases it early. |
| G4 | Local `gost-mcp.yml` with gost-compatible chain/hop schema, `${ENV}` expansion, startup validation, and a model-visible catalog that contains names and descriptions only. |
| G5 | Single binary, stdio transport, works with no other gost component present. |

## 4. Non-goals

- Managing gost services: config CRUD, reload, apply/rollback, logs, metrics, traffic records, quotas.
- Reading or importing a running gost instance's API.
- Remote or team-shared profile distribution; multi-tenant operation.
- Public exposure of TCP/UDP services (only HTTP via the relay's HTTPS endpoint).
- Tunnels that outlive the MCP server process.
- Acting as a SOCKS/HTTP proxy server for other processes.
- MCP Streamable HTTP transport in v0.
- MCP Tasks: no tool blocks long enough to need them (hard ceiling 120 s).

## 5. Anti-goals

These are failure modes even if the code works:

- Implicit direct egress. A caller who omitted `egress` must get an error, never a silent direct connection.
- Credentials in tool arguments or model context.
- An unclassified error. "dial tcp: i/o timeout" is not an answer; `stage=connect, code=timeout, prefix=[jp]` is.
- Blocking a tool call for minutes.
- A public URL that outlives the agent session unbeknownst to the user.

## 6. Constraints (verified in this workspace)

1. **MCP revision 2026-07-28** is current: stateless core, no `initialize`, no `Mcp-Session-Id`; per-request `_meta`; `Mcp-Method`/`Mcp-Name` headers; list results cacheable; state must use explicit handles; `logging`, `sampling`, `roots` are deprecated; legacy HTTP+SSE deprecated. Official Go SDK is at v1.8.x.
2. **In-process chain dialing is available**: `x/config/parsing/chain.ParseChain` builds a `chain.Chainer`; `Chainer.Route(ctx, network, addr)` returns a `Route` whose `Dial` connects through the hops. No listener is bound.
   - Caveat that shapes the design: when a hop selects no node, `Chain.Route` returns early and `chainRoute.Dial` falls back to a **direct dial** (`x/chain/route.go:156`). For an egress-only tool that is a silent bypass, so an empty route must be rejected before dialing and profiles must not contain hop-level `bypass`/`matcher` (see §8).
3. **In-process publish is available**: the `rtcp` listener binds through the chain and stores the server-negotiated public address; `Addr()` returns it after the first successful bind (`x/listener/rtcp/listener.go`). `core/service.Service` exposes `Addr()`.
4. **Relay semantics**: `<label>.gost.run` is HTTPS-terminated by the relay, so the public side works for HTTP services. TCP/UDP need a private `tunnel.id` plus a gost on the access side, so they are out of scope. The docs state the public label is valid for 24 h.
5. **No env expansion in gost config today** (`os.Getenv` is used only for `GOST_*` overrides), so `${ENV}` expansion is implemented in this project.
6. **gost's own API is irrelevant here** — no API client, no API dependency.

## 7. Tool surface

| Tool | Purpose | Annotations |
|------|---------|-------------|
| `gost_run` | One HTTP(S) request through an egress profile | `readOnlyHint=false` (may POST), `destructiveHint=false`, `openWorldHint=true` |
| `gost_trace` | Staged connectivity diagnosis through an egress | `readOnlyHint=true`, `openWorldHint=true` |
| `gost_wisp` | Publish a loopback HTTP service; returns a lease handle | `readOnlyHint=false`, `destructiveHint=false`, `openWorldHint=true` |
| `gost_unwisp` | Release a lease early | `readOnlyHint=false`, `destructiveHint=false`, `idempotentHint=true` |

The names are deliberately opaque product verbs; each description opens with one full sentence stating what it does and that it goes *through an egress profile*, because the name alone does not say "proxy". `gost_trace` in particular must say it traces **cumulative chain prefixes**, not per-hop TTL hops, so the name does not overpromise a traceroute.

### 7.1 `gost_run`

Input:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `url` | string | required | `http` or `https` only |
| `egress` | string | required | profile name; never a URI |
| `method` | string | `GET` | |
| `headers` | object | `{}` | literal values only; no secret indirection in v0 |
| `body` | string | `""` | with `body_encoding` |
| `body_encoding` | `utf8`\|`base64` | `utf8` | |
| `timeout_ms` | int | 30000 | max 120000 |
| `max_bytes` | int | 1048576 | max 8388608 |
| `follow_redirects` | bool | true | max 5 hops |

Output (structured content):

```json
{
  "ok": true,
  "status": 200,
  "status_text": "OK",
  "final_url": "https://example.com/",
  "redirects": [{"status": 302, "location": "/login"}],
  "headers": {"content-type": "text/html; charset=utf-8", "server": "nginx"},
  "body": "...",
  "body_encoding": "utf8",
  "bytes": 12345,
  "truncated": false,
  "sha256": "…",
  "timings": {"connect_ms": 41, "tls_ms": 22, "ttfb_ms": 88, "total_ms": 95},
  "egress": {"name": "jp"},
  "failure": null
}
```

Rules:

- New chain object per call; no connection or health-state carry-over.
- There is deliberately no `resolve_ms`: through SOCKS5/HTTP CONNECT the exit resolves the name, so a local lookup would be a hidden second egress and could contradict the request that actually happened. `connect_ms` covers whatever resolution the chain performs.
- `DisableKeepAlives=true`, no cookie jar, no `HTTP_PROXY`/`HTTPS_PROXY` from the environment.
- Body is read up to `max_bytes+1` to detect truncation.
- Text-ish content types (`text/*`, JSON, XML, JavaScript) are returned as UTF-8; anything else as base64.
- A non-2xx status is a **successful** call (`ok=true`), not a failure.
- Transport failures return `ok=false` with a `failure` object (see §9); they are not MCP protocol errors.
- Only headers on an allowlist are echoed (`content-type`, `content-length`, `server`, `location`, `content-encoding`, `retry-after`, plus any `x-*` up to a cap) to keep the output small.

### 7.2 `gost_trace`

Input:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `target` | string | required | `host:port`, `https://…`, `udp://host:port`, `dns://name` |
| `egress` | string | required | |
| `mode` | `auto`\|`tcp`\|`udp`\|`dns`\|`tls`\|`http` | `auto` | inferred from the target scheme |
| `resolver` | string | first nameserver in `/etc/resolv.conf` | only for `mode=dns`; queried **through** the egress |
| `prefix` | bool | true | cumulative chain prefixes |
| `timeout_ms` | int | 10000 | max 60000; a budget for the whole call, not per dial |
| `payload` | string (base64) | `""` | optional bytes to send for tcp/udp |
| `expect` | string | `""` | optional substring expected in the reply |
| `identity` | bool | false | one extra request to the configured identity endpoint |

Output:

```json
{
  "ok": false,
  "target": "example.com:443",
  "mode": "tls",
  "egress": {"name": "corp"},
  "stages": [
    {"name": "resolve", "ok": true, "ms": 2, "detail": {"addrs": ["1.2.3.4"]}},
    {"name": "connect", "ok": true, "ms": 310, "detail": {"local": "…", "remote": "…"}},
    {"name": "tls", "ok": false, "ms": 0, "error": {"code": "tls_handshake", "message": "EOF"}}
  ],
  "attribution": {"path": ["hop-0", "hop-1"], "stage": "tls", "code": "tls_handshake"},
  "prefixes": [
    {"path": ["direct"], "ok": true, "ms": 35, "served_by": []},
    {"path": ["hop-0"], "ok": true, "ms": 120, "served_by": ["a"]},
    {"path": ["hop-0", "hop-1"], "ok": false, "ms": 3100, "served_by": ["b"], "stage": "connect", "code": "timeout"}
  ],
  "identity": null
}
```

Rules:

- Stage order: `resolve` (local, informational) → `connect` (through the egress) → `tls` → `http`/`read`.
- `resolve` is explicitly labelled local: with SOCKS5/HTTP CONNECT the name is resolved by the proxy, so a local DNS failure does not imply the chain fails, and vice versa.
- `mode=dns` is a separate, explicit query sent **through the egress** to `resolver` (default: the first nameserver in `/etc/resolv.conf`). It answers "what does this exit see for this name", which is a different question from the local `resolve` stage. No public resolver is hardcoded.
- Prefix probing connects only (no payload), one fresh dial per prefix, and stops at the first failing hop prefix. The direct baseline is bounded to min(2s, 20% of the call budget); its failure does not stop the hop probes, and a connect failure is attributed to the first failing hop prefix rather than to `direct` unless `direct` is the only result. The full chain then runs the complete stage test. This is what makes attribution honest: per-hop timing inside one hop group is not observable, but "the first prefix that fails" is.
- Prefixes are re-parsed and re-selected per dial, so with multi-node hops the probe and the final attempt may use different nodes. Each result therefore reports `served_by` (node names, never addresses) and the attribution is documented as best-effort.
- With a single-hop chain, prefixes are `[direct]` and `[hop]`.
- `timeout_ms` is a budget for the whole call: prefix dials draw from the remaining time, and a timeout returns partial results (`ok=false`, `code=timeout`, completed prefixes included) rather than nothing.
- An empty route (a hop selected no node) is `code=no_route`, never a direct dial.
- `udp` requires a UDP-capable egress; the tool attempts the exchange and maps known "proxy cannot do UDP" errors to `code=unsupported` instead of a timeout. It does not precompute capability from the scheme.
- `identity` performs one HTTPS request through the full chain to `trace.identity_url` and reports `{ip, family, country, asn, org}` when the endpoint provides them. It is charged against the same budget.

### 7.3 `gost_wisp` / `gost_unwisp`

`gost_wisp` input:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `local` | string | required | must resolve into `gost_wisp.allow` (default `127.0.0.0/8`, `::1/128`) |
| `ttl_s` | int | 900 | capped by `gost_wisp.max_ttl` (default 3600) |
| `label` | string | `""` | free text for logs and lease listing |
| `verify` | bool | true | one GET through the public URL after publish |

Output:

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

Rules:

- Implementation: build the same service that `gost -L rtcp://:0/<local> -F tunnel+wss://<relay>` produces (via `cmd.BuildConfigFromCmd`, chain registered under a per-lease name), start `Serve()`, then poll `Addr()` until the negotiated public host appears (timeout 15 s). No log parsing.
- `url = https://<host>.<gost_wisp.domain>` where `gost_wisp.domain` defaults to `gost.run`.
- `local` is a `host:port`; the host may be an IP literal or a DNS name such as `localhost`. It is resolved once, every address must be allowed, and the first IPv4 address (else the first IPv6) is pinned.
- Lease lives in an in-memory map guarded by a mutex; a reaper closes the service at TTL; process exit closes all leases. `max_leases` (default 4) bounds concurrency.
- The handle is 16 lowercase hex characters, opaque, random, and not derived from the public label.
- `verify` sends one request to the public URL (no environment proxy, no redirect following) and reports the upstream status; any status, including 401/404, means the tunnel works.
- The relay can re-bind the tunnel and issue a **new** label after a listener error. A per-lease watcher compares `Addr()` every 5 s; on change it updates the stored URL, sets `state=rebound`, and logs a warning. `gost-mcp://leases` exposes `{handle, url, local, label, state, expires_at}` so the current URL is always discoverable instead of the tool handing out a stale one.
- A per-lease goroutine watches the service's `Serve` error. If the relay connection drops entirely the lease is `state=dead`: the service is closed, the chain is unregistered, the lease slot is freed, and the event is logged. `verify` only proves the tunnel at creation time.
- States are `active`, `rebound`, `expired`, and `dead`.
- The tool description states plainly: the URL is public and unauthenticated; the local service must authenticate its own users.

`gost_unwisp` input: `{"handle": "..."}`; output `{"ok": true, "released": true, "url": "..."}`. Idempotent: releasing an unknown or expired handle returns `released=false`, not an error.

## 8. Configuration

Path: `--config`, else `./gost-mcp.yml`, `~/.gost-mcp/gost-mcp.yml`, `/etc/gost-mcp/gost-mcp.yml`.

```yaml
# Egress profiles. Schema is gost's chain/hop schema; `chain:` is the -F sugar.
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

gost_run:
  timeout: 30s
  max_bytes: 1MiB

gost_trace:
  timeout: 10s
  identity_url: "https://ifconfig.co/json"

gost_wisp:
  relay: "tunnel+wss://wisper.gost.run:443"
  domain: "gost.run"
  max_ttl: 1h
  max_leases: 4
  # loopback only by default; widening is config-only
  allow: ["127.0.0.0/8", "::1/128"]

log:
  level: info          # logs go to stderr; stdout is the MCP channel
```

Rules:

- `chain:` and `hops:` are mutually exclusive. Each `chain` entry is **one hop** (gost `-F` semantics); use `hops:` when one hop needs several nodes (a pool). A chain URI scheme must name a registered connector or dialer; an unknown scheme is rejected, never silently mapped to HTTP. An explicit hop node uses `addr: host:port` and `connector: {type: ...}`; `scheme://` belongs only in `chain:` sugar, and `direct`/`virtual` connectors are rejected.
- `${VAR}` is expanded in every scalar string **value** after YAML parsing; keys and comments are untouched, and an unset variable is an error, not an empty string.
- Profile names are unique, lowercase, `[a-z0-9_-]{1,32}`.
- Hop- and node-level `bypass`, `bypasses`, `matcher`, and `filter` are rejected in profiles. They make gost skip a hop (and ultimately dial direct), which would turn a configured egress into a hidden direct connection. Use a separate `direct` profile instead. `node.probe` is rejected too.
- Only `chains`/`hops` semantics are supported; `services`, `authers`, `resolvers`, `hosts`, `plugins`, and `sd` in the file are rejected with a clear error rather than silently ignored.
- `--check` parses, validates, and builds every profile, prints `name`, `description`, hop count, and node count (never addresses or credentials), exits 0/1. Building catches an unregistered scheme or bad node address. Startup fails on the first invalid profile unless `--skip-invalid`.
- The model sees only `name` + `description`, via resource `gost-mcp://egress`. `--expose-topology` additionally includes node addresses for operator debugging.
- No hot reload. Adding a profile means editing the file and restarting the MCP server.
- The relay address is config-only, never a tool argument: a model must not be able to point the tunnel at an arbitrary relay.

## 9. Error model

One struct, used by every tool:

```json
{"stage": "connect", "code": "timeout", "message": "dial tcp 10.0.0.2:1080: i/o timeout", "retryable": true}
```

Stages: `config`, `policy`, `resolve`, `connect`, `proxy_auth`, `tls`, `http`, `read`, `timeout`, `canceled`, `internal`.

Codes are stable strings (`timeout`, `refused`, `nxdomain`, `no_route`, `proxy_auth_failed`, `tls_handshake`, `tls_verify`, `unsupported`, `truncated`, `canceled`, …). `gost_run`/`gost_trace` return `ok=false` with this object as structured content and `isError=false`; MCP protocol errors are reserved for invalid arguments and internal faults.

## 10. Architecture

```
mcp/
  go.mod                      module github.com/go-gost/mcp
  cmd/gost-mcp/main.go        flags, config load, server start
  internal/config/            types, ${ENV}, validation, --check
  internal/egress/            profile -> chain.Chainer; per-call route
  internal/run/               HTTP over a route, timings, body policy
  internal/trace/             staged dial, prefix attribution, identity
  internal/wisp/              provisioner interface, real impl, lease store
  internal/mcpserver/         tool registration, schemas, output mapping
  internal/protocols/         blank imports (curated subset)
  docs/
```

- Go SDK `github.com/modelcontextprotocol/go-sdk` v1.8.x, stdio transport.
- `x` pinned in `go.mod`; no gin, no `x/api`.
- Curated blank imports: the chain-relevant connectors/dialers/handlers plus `rtcp` listener, `tunnel` connector, `wss` dialer, `tcp` handler. Not the whole `register.go` list; `p2p`, `tun`, `tap`, gRPC plugins are excluded in v0.
- `wisp` is behind `type Provisioner interface { Provision(ctx, local string, ttl time.Duration) (Lease, error) }` so the MCP layer can be tested without a relay.
- Every tool handler takes `context.Context` and honours cancellation.

## 11. Security

- The server is a network tool running with the operator's network identity, not a sandbox. This is stated in the README.
- No implicit direct egress; no URI-valued `egress` argument.
- No `env:` header indirection in v0: it would let a prompt-injected model exfiltrate a server-side secret to an arbitrary host. Header values are literal and therefore visible to the model; this is documented.
- `gost_wisp` is loopback-only by default, TTL-capped, lease-capped, logged (label, target, URL, handle, expiry), and never relays to a model-chosen relay.
- Config may contain credentials: `--check` warns when the file is group/world readable; README recommends 0600 and MCP-client env injection for secrets.
- stdout is the MCP channel; gost-mcp's own diagnostics go to stderr or `log.file`. Embedded gost components keep their own logger.
- No shell execution, no config editing, no file paths from tool arguments (except none are accepted).
- Authorization is the MCP host's job; v0 has no HTTP transport, so there is no network listener to protect.

## 12. Testing

- Unit: config parsing/expansion/validation, body truncation and encoding, header filtering, error classification, prefix construction, lease TTL and reaper, handle idempotency.
- Integration (in-process, no external network): a local HTTP server reached through a local SOCKS5 proxy; assert stage success, timings present, 4xx is `ok`, and a dead proxy yields `stage=connect`.
- MCP: drive the server over the SDK's in-memory transport; assert tool catalog, input validation, structured output, and that `egress` is required.
- Wisp: fake `Provisioner` for the MCP layer; the real provisioner gets an opt-in live test (`GOST_MCP_LIVE=1`) against `wisper.gost.run`, never in CI.
- `-race` with `CGO_ENABLED=1`.

## 13. Rollout

1. Skeleton: config, `--check`, MCP server, `gost_run`, `gost_trace`.
2. `gost_wisp` / `gost_unwisp` with the lease reaper and the fake provisioner test.
3. Docs: README, examples for Claude Code / OpenCode / Codex, Dockerfile, goreleaser, one worked diagnosis example.

Version stays `v0.x` until the tool schemas have been exercised by real agents.

## 14. Decisions

Made with the user:

- Repository `go-gost/mcp`; single binary; in-process `x/`; no daemon.
- Tool names: `gost_run`, `gost_trace`, `gost_wisp`; `gost_` prefix.
- Local profile file only, no remote distribution, no hot reload.
- Session-scoped tunnels; no public TCP/UDP; stdio only in v0.

My calls (veto freely):

- **No `x/` changes in v0.** Prefix attribution is best-effort by re-parsing and re-dialing; an empty route is rejected before dialing; profiles may not use bypass/matcher. If exact attribution ever needs an `x` API, it becomes a separately released `core → x → mcp` change.
- `gost_unwisp` exists despite the three-name list: a published URL should be revocable before TTL.
- `egress` is required everywhere; `direct` must be declared explicitly.
- No `env:` secret indirection in v0.
- `gost_wisp` is loopback-only by default; widening is config-only.
- Prefix probing connects only; the full stage test runs once on the full chain.
- `gost_trace` timeout is a single budget for the whole call and may return partial results.
- `mode=dns` queries the first nameserver from `/etc/resolv.conf` through the egress by default; `resolver` overrides it. No public resolver is hardcoded.
- Output includes node **names** (`served_by`) but never addresses.
- `gost_run` has no `resolve_ms`; the chain's resolution is inside `connect_ms`.
- A wisp lease watches for relay re-binds and reports the new URL via `gost-mcp://leases`.
- Identity lookup defaults to `ifconfig.co/json`, is opt-in per call, and is configurable.

Open for the builder: the exact curated protocol import list; the Go error → code mapping table; text/binary sniffing thresholds; the poll interval and failure handling of the lease watcher.
