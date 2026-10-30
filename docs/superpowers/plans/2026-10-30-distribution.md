# Distribution Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make gost-mcp installable from Claude Code, Codex, and OpenCode without hand-written config, and publishable through the standard Go/MCP distribution channels.

**Architecture:** Three independent deliverables. (1) The binary starts with an implicit `direct` profile when no config file exists, and advertises MCP `instructions`. (2) Tagged releases build binaries and a multi-arch GHCR image via GitHub Actions; `.goreleaser.yaml` already exists. (3) An npm wrapper (`@go-gost/mcp`) resolves a per-platform optional dependency so `npx -y @go-gost/mcp` works on every supported OS/arch, with no postinstall download.

**Tech Stack:** Go 1.26.3, go-sdk v1.8.0, GitHub Actions, goreleaser v2, npm (Node >= 18).

**Spec:** `docs/superpowers/specs/2026-10-29-gost-mcp-design.md` plus the distribution analysis in the 2026-10-30 session (official MCP Registry consumes npm/OCI packages; Claude Code has a plugin marketplace; Codex and OpenCode use config only).

## Global Constraints

- stdio only; never write non-MCP bytes to stdout.
- No new Go dependencies.
- npm package name `@go-gost/mcp`; platform packages `@go-gost/mcp-<os>-<arch>`; `mcpName` is `io.github.go-gost/mcp`.
- Supported platforms: linux/darwin/windows × amd64/arm64.
- No `postinstall` network access; binaries ship inside platform packages.
- Config fallback only applies when `--config` is empty; an explicit missing path is still an error.

## Review Focus

- A user runs `npx -y @go-gost/mcp` with no config: startup must succeed and expose a `direct` profile.
- An explicit `--config /missing.yml` must still fail, or typos silently fall back to direct.
- `gost-wisp` must remain loopback-only and bounded after the npm/Docker install paths change.
- The npm shim must forward stdin/stdout unchanged and propagate the child exit status/signal.
- Release automation must not publish on non-tag pushes and must not require an npm token to build binaries.

---

### Task 1: Zero-config startup and server instructions

**Files:**
- Modify: `internal/config/load.go`
- Modify: `internal/mcpserver/server.go`
- Test: `internal/config/config_test.go`, `internal/mcpserver/server_test.go`

**Interfaces:**
- Produces: `config.ErrNoConfig` (sentinel, wrapped by `ResolvePath`).
- Produces: `mcpserver.Instructions` (const string used as `mcp.ServerOptions.Instructions`).
- `LoadWith("", opts)` returns a `*Config` with one `direct` profile when no file is found.

- [ ] **Step 1: Write the failing config tests**

```go
func TestLoadDefaultsToDirectWithoutConfig(t *testing.T) {
    dir := t.TempDir()
    t.Chdir(dir)
    t.Setenv("HOME", dir)
    var warnings []string
    c, err := LoadWith("", LoadOptions{Warnf: func(f string, a ...any) { warnings = append(warnings, f) }})
    if err != nil { t.Fatalf("LoadWith: %v", err) }
    if len(c.Egress) != 1 || c.Egress[0].Name != "direct" || c.Egress[0].Chain == nil || len(c.Egress[0].Chain) != 0 {
        t.Fatalf("Egress = %+v, want one explicit direct profile", c.Egress)
    }
    if len(warnings) != 1 { t.Fatalf("warnings = %v, want one", warnings) }
}

func TestLoadExplicitMissingConfigStillFails(t *testing.T) {
    if _, err := LoadWith(filepath.Join(t.TempDir(), "missing.yml"), LoadOptions{}); err == nil {
        t.Fatal("LoadWith succeeded, want an error for an explicit missing path")
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/config -run 'TestLoadDefaultsToDirectWithoutConfig|TestLoadExplicitMissingConfigStillFails'`
Expected: the first fails because `LoadWith` returns "no configuration file found".

- [ ] **Step 3: Implement the fallback**

In `load.go`: add `var ErrNoConfig = errors.New("config: no configuration file found")`; have `ResolvePath("")` return `fmt.Errorf("%w (looked in %s)", ErrNoConfig, ...)`; in `LoadWith`, if `errors.Is(err, ErrNoConfig) && path == ""`, call `opts.Warnf("no configuration file found; using the implicit direct profile")`, build `&Config{Egress: []EgressProfile{{Name: "direct", Description: "Implicit direct egress", Chain: []string{}}}}`, `applyDefaults()`, validate, and return it.

- [ ] **Step 4: Write the failing instructions test**

In `server_test.go`:

```go
func TestServerAdvertisesInstructions(t *testing.T) {
    session := newTestSession(t, testConfig(), false)
    got := session.InitializeResult().Instructions
    if !strings.Contains(got, "gost-mcp://egress") || !strings.Contains(got, "gost-unwisp") {
        t.Fatalf("instructions = %q", got)
    }
    if len(got) > 1024 { t.Fatalf("instructions too long: %d", len(got)) }
}
```

- [ ] **Step 5: Run it to verify it fails**

Run: `go test ./internal/mcpserver -run TestServerAdvertisesInstructions`
Expected: empty instructions.

- [ ] **Step 6: Add the instructions**

In `server.go`, add `const Instructions = "..."` (mention: profile names come from `gost-mcp://egress`, never inline URIs; `gost-trace` finds the first failing stage; `gost-wisp` publishes a public unauthenticated URL, use only on explicit request, short TTL, release with `gost-unwisp`; first 512 chars self-contained) and pass `&mcp.ServerOptions{Instructions: Instructions}` to `mcp.NewServer`.

- [ ] **Step 7: Run the package tests**

Run: `go test ./internal/config ./internal/mcpserver`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/config internal/mcpserver
git commit -m "feat: start with implicit direct profile and advertise instructions"
```

---

### Task 2: Release pipeline

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: the existing `.goreleaser.yaml` and `Dockerfile`.
- Produces: GitHub Release archives + `ghcr.io/go-gost/mcp` on `v*` tags.

- [ ] **Step 1: Write the workflow**

Tag trigger `v*`; `permissions: contents: write, packages: write`; job `goreleaser` (checkout fetch-depth 0, setup-go from `go.mod`, `goreleaser/goreleaser-action@v6` with `release --clean`); job `image` (needs goreleaser, buildx, login to GHCR with `GITHUB_TOKEN`, metadata-action semver tags, build-push linux/amd64+arm64).

- [ ] **Step 2: Validate the YAML**

Run: `go run github.com/rhysd/actionlint/cmd/actionlint@latest .github/workflows/release.yml`
Expected: no findings.

- [ ] **Step 3: Dry-run goreleaser locally**

Run: `goreleaser check` (or `go run github.com/goreleaser/goreleaser/v2@latest check`).
Expected: config valid.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: build release binaries and GHCR image on tags"
```

---

### Task 3: npm wrapper

**Files:**
- Create: `npm/package.json`, `npm/bin/gost-mcp.js`, `npm/scripts/stage.mjs`, `npm/README.md`
- Create: `.github/workflows/npm-publish.yml`

**Interfaces:**
- Produces: `npx -y @go-gost/mcp` runs the platform binary with inherited stdio.
- `stage.mjs --version V --binaries DIR --out DIR` writes one package per platform plus the main package.

- [ ] **Step 1: Write the shim and packages**

Main package has `bin`, `optionalDependencies` for the six platforms, `engines.node >= 18`, `mcpName`. Platform packages have `os`/`cpu`, `exports: {"./package.json": "./package.json"}`, and `bin/gost-mcp[.exe]`.

- [ ] **Step 2: Write the staging script**

Map `linux/darwin/win32` × `x64/arm64`; copy `DIR/<os>-<arch>/gost-mcp[.exe]`; generate package.json with the release version; chmod 0755. Fail if any binary is missing.

- [ ] **Step 3: Test the shim locally**

Run: `node npm/bin/gost-mcp.js --version` with a staged linux-x64 package linked into `node_modules`.
Expected: prints the same version as `./gost-mcp --version`, and `echo | node ... ` forwards stdin.

- [ ] **Step 4: Add the publish workflow**

`workflow_dispatch` only, input `version`; downloads the release archives with `gh`, extracts to the staging layout, runs `stage.mjs`, `npm publish --access public` for each platform then the main package using `NODE_AUTH_TOKEN`. No publish on push.

- [ ] **Step 5: Commit**

```bash
git add npm .github/workflows/npm-publish.yml
git commit -m "feat: add npm platform wrapper for npx installs"
```

---

### Task 4: Distribution runbook

**Files:**
- Create: `docs/distribution.md`
- Modify: `README.md` (Install section links the runbook)

- [ ] **Step 1: Write the runbook** — release steps, npm publish, Claude Code plugin snippet, Codex `config.toml`, OpenCode `mcp add`, MCP Registry `server.json` notes, and the Docker/wisp loopback caveat.
- [ ] **Step 2: Verify commands are copy-pasteable** — run the `go install` and `opencode mcp add` lines against the local build.
- [ ] **Step 3: Commit** with `docs: add distribution and install runbook`.

---

### Task 5: Final verification

- [ ] `go test ./...`, `go vet ./...`, `gofmt -l .` empty.
- [ ] `HOME=$(mktemp -d) ./gost-mcp --check` prints one `direct` profile.
- [ ] `HOME=$(mktemp -d) ./gost-mcp --config /nope.yml --check` exits 1.
- [ ] `npm pack --dry-run` in each staged package lists only expected files.
- [ ] `actionlint` clean on both workflows.
