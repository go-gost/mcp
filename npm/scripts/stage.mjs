#!/usr/bin/env node
// Stage the goreleaser binaries into publishable npm packages.
//
// Layout expected under --binaries (one directory per platform, produced by
// the release workflow after extracting the archives):
//
//   binaries/linux-x64/gost-mcp
//   binaries/win32-arm64/gost-mcp.exe
//
// The main package gets the shim and an optionalDependency on every platform
// package, so npm installs exactly one binary.
import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const npmRoot = path.resolve(here, "..");
const repo = "https://github.com/go-gost/mcp";

const PLATFORMS = [
  ["linux", "x64", "gost-mcp"],
  ["linux", "arm64", "gost-mcp"],
  ["darwin", "x64", "gost-mcp"],
  ["darwin", "arm64", "gost-mcp"],
  ["win32", "x64", "gost-mcp.exe"],
  ["win32", "arm64", "gost-mcp.exe"],
];

function fail(message) {
  console.error(`stage: ${message}`);
  process.exit(1);
}

function usage() {
  console.error("usage: stage.mjs --version <semver> --binaries <dir> --out <dir>");
  process.exit(2);
}

const flags = {};
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 2) {
  if (!argv[i].startsWith("--") || i + 1 >= argv.length) {
    usage();
  }
  flags[argv[i].slice(2)] = argv[i + 1];
}

const version = flags.version;
const binaries = flags.binaries && path.resolve(flags.binaries);
const out = flags.out && path.resolve(flags.out);
if (!version || !binaries || !out) {
  usage();
}
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  fail(`invalid semver ${JSON.stringify(version)}`);
}

const main = JSON.parse(await readFile(path.join(npmRoot, "package.json"), "utf8"));
main.version = version;
main.repository = { type: "git", url: `git+${repo}.git` };
main.homepage = repo;
main.bugs = { url: `${repo}/issues` };
for (const [os, arch] of PLATFORMS) {
  main.optionalDependencies[`@go-gost/mcp-${os}-${arch}`] = version;
}

const mainDir = path.join(out, "mcp");
await mkdir(path.join(mainDir, "bin"), { recursive: true });
await copyFile(path.join(npmRoot, "bin", "gost-mcp.js"), path.join(mainDir, "bin", "gost-mcp.js"));
await chmod(path.join(mainDir, "bin", "gost-mcp.js"), 0o755);
await copyFile(path.join(npmRoot, "README.md"), path.join(mainDir, "README.md"));
await writeFile(
  path.join(mainDir, "package.json"),
  `${JSON.stringify(main, null, 2)}\n`,
);

for (const [os, arch, binary] of PLATFORMS) {
  const source = path.join(binaries, `${os}-${arch}`, binary);
  if (!existsSync(source)) {
    fail(`missing ${source}`);
  }

  const dir = path.join(out, `mcp-${os}-${arch}`);
  await mkdir(path.join(dir, "bin"), { recursive: true });
  await copyFile(source, path.join(dir, "bin", binary));
  await chmod(path.join(dir, "bin", binary), 0o755);

  const pkg = {
    name: `@go-gost/mcp-${os}-${arch}`,
    version,
    description: `gost-mcp binary for ${os}/${arch}. Install @go-gost/mcp instead of this package.`,
    license: "MIT",
    os: [os],
    cpu: [arch],
    files: ["bin/"],
    exports: { "./package.json": "./package.json" },
    repository: { type: "git", url: `git+${repo}.git` },
    homepage: repo,
  };
  await writeFile(path.join(dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
}

console.log(`staged @go-gost/mcp@${version} and ${PLATFORMS.length} platform packages in ${out}`);
