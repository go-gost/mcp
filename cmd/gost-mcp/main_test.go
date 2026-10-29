package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-gost/mcp/internal/config"
)

// TestCheckBuildsProfiles pins that --check is not just schema validation: it
// builds every profile, so an unregistered scheme is caught before startup.
func TestCheckBuildsProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gost-mcp.yml")
	if err := os.WriteFile(path, []byte(`
egress:
  - name: bad
    description: "unsupported scheme"
    chain: ["grpc://127.0.0.1:1080"]
`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--config", path, "--check"}, &stdout, &stderr); code != 1 {
		t.Fatalf("--check exit = %d, want 1; stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "grpc") {
		t.Errorf("stderr = %q, want it to name the unsupported scheme", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--config", path, "--check", "--skip-invalid"}, &stdout, &stderr); code != 1 {
		t.Fatalf("--check --skip-invalid exit = %d, want 1 when no profile is usable", code)
	}
}

// TestCheckBuildsCorrectedHopsExample runs --check against the explicit-hops
// form documented in the README and gost-mcp.example.yml.
func TestCheckBuildsCorrectedHopsExample(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--config", "../../internal/egress/testdata/example.yml", "--check"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--check exit = %d, want 0; stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "corp") {
		t.Errorf("stdout = %q, want the corp profile", stdout.String())
	}
}

// TestNewLoggerWritesFile pins that log.file is wired to a real handler.
func TestNewLoggerWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gost-mcp.log")
	logger, closer, err := newLogger(config.LogConfig{Level: "info", File: path}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	if closer == nil {
		t.Fatal("newLogger returned no closer for log.file")
	}
	logger.Info("hello from the logger")
	closer.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "hello from the logger") {
		t.Errorf("log file = %q, want the record", data)
	}
}
