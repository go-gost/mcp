# @go-gost/mcp

npm wrapper for [gost-mcp](https://github.com/go-gost/mcp), a stdio MCP server
with four network tools:

- `gost-run` — one HTTP(S) request through a named egress profile
- `gost-trace` — staged DNS/TCP/TLS/HTTP diagnosis with cumulative chain prefixes
- `gost-wisp` / `gost-unwisp` — publish a loopback HTTP service at a temporary
  public URL, then release it

## Install

```sh
npx -y @go-gost/mcp
```

The first run needs no configuration: gost-mcp starts with an implicit
`direct` profile. Add proxy profiles in `~/.gost-mcp/gost-mcp.yml` (or pass
`--config`), then restart the client. See
[gost-mcp.example.yml](https://github.com/go-gost/mcp/blob/main/gost-mcp.example.yml).

Supported platforms: linux/darwin/win32 on x64 and arm64. Each platform ships
its own optional dependency, so npm installs exactly one binary and no
postinstall script runs.

## Clients

Claude Code, Codex, and OpenCode all start local stdio servers. Point them at
`npx -y @go-gost/mcp`; no other arguments are required for the direct profile.

`gost-wisp` URLs are public and unauthenticated. Only publish services the user
explicitly asked to expose, keep the TTL short, and release the lease with
`gost-unwisp` when done.
