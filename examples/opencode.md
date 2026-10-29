# OpenCode

OpenCode declares local MCP servers in `opencode.json` (project) or `~/.config/opencode/opencode.json` (global). A local server uses `type: "local"`, a command **array**, and an `environment` object.

## Configuration

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "gost": {
      "type": "local",
      "command": ["/usr/local/bin/gost-mcp", "--config", "/etc/gost-mcp/gost-mcp.yml"],
      "enabled": true,
      "environment": {
        "JP_USER": "alice",
        "JP_PASS": "s3cret"
      }
    }
  }
}
```

The `environment` values are what `${JP_USER}` and `${JP_PASS}` in `gost-mcp.yml` resolve against:

```yaml
egress:
  - name: jp
    description: "Tokyo residential exit (SOCKS5)"
    chain:
      - "socks5://${JP_USER}:${JP_PASS}@tokyo.example.com:1080"
```

Notes:

- `command` is an array, not a shell string. OpenCode does not run a shell, so do not add quoting or `&&`.
- An unset variable makes the server exit at startup with `config: undefined environment variable(s): JP_USER`. That is deliberate.
- A global OpenCode config file can be read by other local users depending on your umask; keep it mode `0600` if it contains credentials, or export the values in the shell that starts OpenCode and use the config's environment substitution.
- Restart OpenCode after changing the config; `gost-mcp.yml` itself is also read only at startup.

## Worked prompts

**Reach through an egress (`gost_run`)**

> Reach https://ifconfig.co through jp and show me the exit IP.

The tool call:

```json
{
  "egress": "jp",
  "url": "https://ifconfig.co/json"
}
```

A non-2xx status is still `ok=true`; only a transport failure sets `ok=false` with a classified `failure`.

**Diagnose a target (`gost_trace`)**

> Trace example.com:443 through corp and tell me which chain prefix fails.

The tool call:

```json
{
  "egress": "corp",
  "target": "example.com:443",
  "identity": true
}
```

The result names the first failing cumulative prefix (`direct`, `hop-0`, `hop-0 → hop-1`, ...) and the stage, for example `connect` / `timeout`. A bare `example.com:443` is a TCP trace; use `tls://example.com:443` or an `https://` URL to exercise the TLS stage. `corp` is the multi-hop example profile from the README; use a profile you actually configured.

**Publish a local service (`gost_wisp`)**

> Publish 127.0.0.1:3000 at a public URL for 10 minutes.

The tool call:

```json
{
  "local": "127.0.0.1:3000",
  "ttl_s": 600,
  "label": "preview"
}
```

The result carries `url`, `handle`, `expires_at`, and `state`. A bare `:3000` is rejected: `local` must include a host and must resolve inside `gost_wisp.allow` (loopback by default).

To revoke early:

> Release the lease you just created.

OpenCode calls `gost_unwisp` with the handle. The URL is public and unauthenticated; the local service must authenticate its own users.
