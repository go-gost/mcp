#!/usr/bin/env node
"use strict";

// The real binary lives in a per-platform package so npm filters the optional
// dependencies down to the one this machine can run. Keep stdio inherited:
// stdin/stdout are the MCP transport.
const { spawn } = require("node:child_process");
const path = require("node:path");

const key = `${process.platform}-${process.arch}`;
const pkg = `@go-gost/mcp-${key}`;
const supported = [
  "linux-x64",
  "linux-arm64",
  "darwin-x64",
  "darwin-arm64",
  "win32-x64",
  "win32-arm64",
];

let binary;
try {
  const pkgJSON = require.resolve(`${pkg}/package.json`);
  binary = path.join(
    path.dirname(pkgJSON),
    "bin",
    process.platform === "win32" ? "gost-mcp.exe" : "gost-mcp",
  );
} catch {
  console.error(`gost-mcp: no binary for ${process.platform}/${process.arch} (looked for ${pkg}).`);
  console.error(`gost-mcp: supported platforms: ${supported.join(", ")}.`);
  process.exit(1);
}

const child = spawn(binary, process.argv.slice(2), { stdio: "inherit" });

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    if (!child.killed) {
      child.kill(signal);
    }
  });
}

child.on("error", (err) => {
  console.error(`gost-mcp: ${err.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
