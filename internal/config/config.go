// Package config loads and validates the gost-mcp configuration file.
//
// The file holds the egress profiles (gost chain/hop schema) plus the small
// amount of tuning the tools need. It is read once at startup: there is no
// hot reload, so a profile change requires a restart.
package config

import (
	"fmt"
	"time"

	xconfig "github.com/go-gost/x/config"
	"github.com/go-gost/x/config/cmd"
)

// Defaults applied by Load when a section or key is omitted.
const (
	DefaultRunTimeout       = 30 * time.Second
	DefaultRunMaxBytes      = 1 << 20 // 1 MiB
	DefaultTraceTimeout     = 10 * time.Second
	DefaultTraceIdentityURL = "https://ifconfig.co/json"
	DefaultWispRelay        = "tunnel+wss://wisper.gost.run:443"
	DefaultWispDomain       = "gost.run"
	DefaultWispMaxTTL       = time.Hour
	DefaultWispMaxLeases    = 4
	DefaultLogLevel         = "info"
)

// DefaultWispAllow is the loopback-only publish allow list.
var DefaultWispAllow = []string{"127.0.0.0/8", "::1/128"}

// Config is the root of gost-mcp.yml.
type Config struct {
	Egress []EgressProfile `yaml:"egress"`
	Run    RunConfig       `yaml:"gost_run"`
	Trace  TraceConfig     `yaml:"gost_trace"`
	Wisp   WispConfig      `yaml:"gost_wisp"`
	Log    LogConfig       `yaml:"log"`
}

// EgressProfile is one named egress. Exactly one of Chain and Hops must be
// set. A non-nil but empty Chain is the explicit "direct" profile; a nil
// Chain means the key was omitted, which is a validation error.
type EgressProfile struct {
	Name        string               `yaml:"name"`
	Description string               `yaml:"description"`
	Chain       []string             `yaml:"chain"`
	Hops        []*xconfig.HopConfig `yaml:"hops"`
}

// RunConfig tunes gost_run.
type RunConfig struct {
	Timeout  time.Duration `yaml:"timeout"`
	MaxBytes int64         `yaml:"max_bytes"`
}

// TraceConfig tunes gost_trace.
type TraceConfig struct {
	Timeout     time.Duration `yaml:"timeout"`
	IdentityURL string        `yaml:"identity_url"`
}

// WispConfig tunes gost_wisp / gost_unwisp.
type WispConfig struct {
	Relay     string        `yaml:"relay"`
	Domain    string        `yaml:"domain"`
	MaxTTL    time.Duration `yaml:"max_ttl"`
	MaxLeases int           `yaml:"max_leases"`
	Allow     []string      `yaml:"allow"`
}

// LogConfig tunes logging. Logs always go to stderr; stdout is the MCP
// channel.
type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// ChainConfig converts the profile into the gost chain schema.
//
// Explicit hops are passed through unchanged. A sugar chain is built by
// cmd.BuildConfigFromCmd, where each URI is one hop (the -F semantics). A
// non-nil empty chain is the direct profile: a named chain with no hops.
func (p *EgressProfile) ChainConfig() (*xconfig.ChainConfig, error) {
	switch {
	case p.Hops != nil:
		if len(p.Hops) == 0 {
			return nil, fmt.Errorf("egress %q: hops must not be empty", p.Name)
		}
		return &xconfig.ChainConfig{Name: p.Name, Hops: p.Hops}, nil

	case p.Chain != nil:
		if len(p.Chain) == 0 {
			return &xconfig.ChainConfig{Name: p.Name}, nil
		}
		cfg, err := cmd.BuildConfigFromCmd(nil, p.Chain)
		if err != nil {
			return nil, fmt.Errorf("egress %q: %w", p.Name, err)
		}
		if len(cfg.Chains) == 0 || len(cfg.Chains[0].Hops) == 0 {
			return nil, fmt.Errorf("egress %q: chain produced no hops", p.Name)
		}
		chain := cfg.Chains[0]
		chain.Name = p.Name
		return chain, nil

	default:
		return nil, fmt.Errorf("egress %q: exactly one of chain or hops is required", p.Name)
	}
}
