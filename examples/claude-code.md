# Claude Code

Claude Code supports local MCP servers over stdio. Use **user scope** for a personal install so credentials and the config path do not land in a project file that might be committed.

## Add the server

```sh
claude mcp add --scope user gost \
  --env JP_USER=alice \
  --env JP_PASS=s3cret \
  -- /usr/local/bin/gost-mcp --config /etc/gost-mcp/gost-mcp.yml
```

Verify it is connected:

```sh
claude mcp list
```

## Project `.mcp.json` (alternative)

If you prefer a checked-in project entry, create `.mcp.json` at the repository root. This file is shared with everyone who opens the project, so do **not** put real credentials in it.

```json
{
  "mcpServers": {
    "gost": {
      "type": "stdio",
      "command": "/usr/local/bin/gost-mcp",
      "args": ["--config", "/etc/gost-mcp/gost-mcp.yml"],
      "env": {
        "JP_USER": "alice",
        "JP_PASS": "s3cret"
      }
    }
  }
}
```

The `env` block is what `${JP_USER}` and `${JP_PASS}` in `gost-mcp.yml` resolve against:

```yaml
egress:
  - name: jp
    description: "Tokyo residential exit (SOCKS5)"
    chain:
      - "socks5://${JP_USER}:${JP_PASS}@tokyo.example.com:1080"
```

If a variable is missing, the server exits at startup with `config: undefined environment variable(s): JP_USER`. That is intentional: a missing credential never becomes an anonymous connection.

## Worked prompts

**Reach through an egress (`gost_run`)**

> Reach https://ifconfig.co through jp and show me the exit IP.

Claude calls:

```json
{
  "egress": "jp",
  "url": "https://ifconfig.co/json"
}
```

**Diagnose a target (`gost_trace`)**

> Trace example.com:443 through corp and tell me which chain prefix fails.

Claude calls:

```json
{
  "egress": "corp",
  "target": "example.com:443",
  "identity": true
}
```

The answer names the first failing prefix, for example `hop-0 → hop-1`, stage `connect`, code `timeout`. `corp` is the multi-hop example profile from the README; use the name of a profile you actually configured.

**Publish a local service (`gost_wisp`)**

> Publish 127.0.0.1:3000 at a public URL for 10 minutes.

Claude calls:

```json
{
  "local": "127.0.0.1:3000",
  "ttl_s": 600,
  "label": "preview"
}
```

It returns a URL and a handle such as `w_7f3c2a1b9d40`. A bare `:3000` is not accepted: `local` must include a host, and the address must resolve inside `gost_wisp.allow` (loopback by default).

To revoke early:

> Release the lease you just created.

Claude calls `gost_unwisp` with the handle. The URL is public and unauthenticated — the local service must authenticate its own users, and the lease ends when the TTL expires or the server process exits.
