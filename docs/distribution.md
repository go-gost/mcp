# Distribution and install

gost-mcp ships as a static binary, a multi-arch container image, and an npm
wrapper. The npm wrapper is the lowest-friction path for agent clients because
Claude Code, Codex, and OpenCode all support local stdio servers but none of
them installs a Go toolchain.

## Release

Tagging is the only trigger:

```sh
git tag v0.1.0
git push origin v0.1.0
```

`.github/workflows/release.yml` then:

1. runs goreleaser, which publishes GitHub Release archives for
   linux/darwin/windows × amd64/arm64 (`gost-mcp_<version>_<os>_<arch>.tar.gz`,
   Windows uses `.zip`) plus `checksums.txt`;
2. builds and pushes `ghcr.io/go-gost/mcp` for linux/amd64 and linux/arm64,
   tagged `0.1.0`, `0.1`, `0`, and `latest`.

Verify:

```sh
gh release view v0.1.0
docker run --rm -i ghcr.io/go-gost/mcp:0.1.0 --version
```

The container reads `/etc/gost-mcp/gost-mcp.yml`; the image ships a
`direct`-only example, so mount a real file over it for proxy profiles:

```sh
docker run --rm -i \
  -v "$PWD/gost-mcp.yml:/etc/gost-mcp/gost-mcp.yml:ro" \
  -e JP_USER -e JP_PASS \
  ghcr.io/go-gost/mcp:0.1.0
```

`-i` is required and `-t` must not be used: stdio is the MCP transport.

## npm

Publishing uses npm **staged publishing**: CI stages with a stage-only token,
and a maintainer approves each version with 2FA before it goes live. This is
npm's 2026 model for automation tokens and keeps a 2FA-capable token out of
CI.

One-time setup:

1. Create the `@go-gost` organization on npmjs.com and invite the maintainers.
2. Create a granular access token with **Read and write (stage only)** for all
   `@go-gost` packages and add it as the repository secret `NPM_TOKEN`.

For an existing GitHub release:

1. Run the **npm-publish** workflow with `version` set to the release without
   the leading `v` (for example `0.1.0`).
2. It downloads the release archives, stages six platform packages plus the
   main package, and prints each stage ID.
3. A maintainer approves every stage with 2FA, either in the npmjs.com
   **Staged Packages** tab, or with `npm stage approve <stage-id> --otp <code>`
   (npm >= 11.15.0, Node >= 22.14.0).
4. Approve the platform packages before the main package, so a first
   `npx @go-gost/mcp` finds its optional dependency.

Verify after approval:

```sh
npx -y @go-gost/mcp --version
```

The main package has no `postinstall`. `@go-gost/mcp` declares six
`optionalDependencies`; npm installs only the one matching `os`/`cpu`, and
`bin/gost-mcp.js` execs that binary with inherited stdio. The main package
carries `mcpName: io.github.go-gost/mcp`, which the official MCP Registry uses
to verify package ownership.

Supported combinations: `linux-x64`, `linux-arm64`, `darwin-x64`,
`darwin-arm64`, `win32-x64`, `win32-arm64`.

## Client install

No configuration is required: without a config file gost-mcp starts with an
implicit `direct` profile and warns on stderr. Add proxy profiles in
`~/.gost-mcp/gost-mcp.yml` (see `gost-mcp.example.yml`) and restart the client.

Claude Code:

```sh
claude mcp add gost -- npx -y @go-gost/mcp
```

Codex:

```sh
codex mcp add gost -- npx -y @go-gost/mcp
```

OpenCode:

```sh
opencode mcp add gost -- npx -y @go-gost/mcp
```

Or in `opencode.json`:

```jsonc
{
  "mcp": {
    "servers": {
      "gost": {
        "type": "local",
        "command": ["npx", "-y", "@go-gost/mcp"]
      }
    }
  }
}
```

Claude Code plugin marketplace (not published yet): the repository needs a
`.claude-plugin/marketplace.json` whose plugin entry contains a `.mcp.json`
with the same `npx` command. Users would then run
`/plugin marketplace add go-gost/mcp` and install the plugin. Public listing
goes through Anthropic's directory review.

## Official MCP Registry (not published yet)

The registry stores metadata only; downstream directories (GitHub MCP Registry,
Glama, PulseMCP, Docker catalogs) sync from it. Add a `server.json` with:

- `name: io.github.go-gost/mcp` (GitHub OAuth namespace, no DNS setup);
- `version` matching the release;
- two `packages`: `registryType: npm` / `identifier: @go-gost/mcp` /
  `runtimeHint: npx`, and `registryType: oci` /
  `identifier: ghcr.io/go-gost/mcp:<version>`;
- `transport: { "type": "stdio" }` on both.

Then authenticate and publish with the `mcp-publisher` CLI (GitHub OIDC in CI):

```sh
mcp-publisher validate
mcp-publisher publish
```

The npm package already sets `mcpName`; the OCI image needs the ownership
label required by the registry's package rules before publishing.

## Caveats

- **Docker and `gost-wisp` do not mix well.** The wisp tools publish loopback
  targets, and a container's `127.0.0.1` is not the host. On Linux use
  `--network host`; on macOS and Windows the container cannot reach host
  loopback at all. Prefer the npm/native binary when wisp is needed.
- A wisp URL is public and unauthenticated for the life of the lease. Publish
  only on an explicit request, keep the TTL short, and release with
  `gost-unwisp`.
- The npm wrapper version must match the release tag; the publish workflow
  stamps the version into every package, so never edit `npm/package.json`
  versions by hand for a release.
