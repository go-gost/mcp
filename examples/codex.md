# Codex

Codex reads MCP servers from `~/.codex/config.toml`. A local server is a `[mcp_servers.<name>]` table with `command`, `args`, and `env`.

## Configuration

```toml
[mcp_servers.gost]
command = "/usr/local/bin/gost-mcp"
args = ["--config", "/etc/gost-mcp/gost-mcp.yml"]
env = { JP_USER = "alice", JP_PASS = "s3cret" }
```

The `env` values are what `${JP_USER}` and `${JP_PASS}` in `gost-mcp.yml` resolve against:

```yaml
egress:
  - name: jp
    description: "Tokyo residential exit (SOCKS5)"
    chain:
      - "socks5://${JP_USER}:${JP_PASS}@tokyo.example.com:1080"
```

Notes:

- `args` is a TOML array, one element per argument. There is no shell involved.
- If a variable is missing, the server exits at startup with `config: undefined environment variable(s): JP_USER`. That is intentional.
- `~/.codex/config.toml` may contain credentials; keep it mode `0600`.
- Restart Codex after editing the config. `gost-mcp.yml` is also read only once, at server startup.

Optional timeouts, if your shell tools need longer than the defaults:

```toml
[mcp_servers.gost]
command = "/usr/local/bin/gost-mcp"
args = ["--config", "/etc/gost-mcp/gost-mcp.yml"]
env = { JP_USER = "alice", JP_PASS = "s3cret" }
startup_timeout_sec = 20
tool_timeout_sec = 120
```

`gost-mcp` bounds every call internally (120 s for `gost-run`, 60 s for `gost-trace`), so the tool timeout only needs to cover the MCP round trip.

## Worked prompts

**Reach through an egress (`gost-run`)**

> Reach https://ifconfig.co through jp and show me the exit IP.

The tool call:

```json
{
  "egress": "jp",
  "url": "https://ifconfig.co/json"
}
```

A non-2xx status is still a successful call. Transport failures return `ok=false` with `stage`, `code`, `message`, and `retryable`.

**Diagnose a target (`gost-trace`)**

> Trace example.com:443 through corp and tell me which chain prefix fails.

The tool call:

```json
{
  "egress": "corp",
  "target": "example.com:443",
  "identity": true
}
```

Codex gets the completed stages, the first failing cumulative prefix, and optionally the public egress identity (`ip`, `country`, `asn`, ...). `corp` is the multi-hop example profile from the README; use a profile you actually configured.

**Publish a local service (`gost-wisp`)**

> Publish 127.0.0.1:3000 at a public URL for 10 minutes.

The tool call:

```json
{
  "local": "127.0.0.1:3000",
  "ttl_s": 600,
  "label": "preview"
}
```

The result carries `url`, `handle`, `expires_at`, and `state`. A bare `:3000` is rejected: `local` must include a host and must resolve inside `gost-wisp.allow` (loopback by default).

To revoke early:

> Release the lease you just created.

Codex calls `gost-unwisp` with the handle. The URL is public and unauthenticated, so the local service must authenticate its own users, and the lease ends at TTL or when the server process exits.
