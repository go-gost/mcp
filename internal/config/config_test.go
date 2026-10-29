package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xconfig "github.com/go-gost/x/config"
)

// validProfile returns a profile that passes Validate, so a test can mutate
// exactly one aspect of it.
func validProfile(name string) EgressProfile {
	return EgressProfile{
		Name:        name,
		Description: "test egress",
		Chain:       []string{"socks5://proxy.example.com:1080"},
	}
}

func TestLoadExpandsEnv(t *testing.T) {
	t.Setenv("JP_PASS", "s3cret")

	c, err := Load("testdata/env.yml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Egress) != 1 {
		t.Fatalf("len(Egress) = %d, want 1", len(c.Egress))
	}
	if got := c.Egress[0].Chain; len(got) != 1 || got[0] != "socks5://u:s3cret@host:1080" {
		t.Fatalf("Chain = %q, want [socks5://u:s3cret@host:1080]", got)
	}
}

func TestLoadUnsetEnvIsError(t *testing.T) {
	old, had := os.LookupEnv("JP_PASS")
	if err := os.Unsetenv("JP_PASS"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv("JP_PASS", old)
		}
	})

	_, err := Load("testdata/env.yml")
	if err == nil {
		t.Fatal("Load succeeded, want an error naming the unset variable")
	}
	if !strings.Contains(err.Error(), "JP_PASS") {
		t.Fatalf("error = %v, want it to mention JP_PASS", err)
	}
}

func TestLoadUnknownSectionIsError(t *testing.T) {
	_, err := Load("testdata/unknown.yml")
	if err == nil {
		t.Fatal("Load succeeded, want an unknown-field error")
	}
	if !strings.Contains(err.Error(), "services") {
		t.Fatalf("error = %v, want it to name the unknown field", err)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	c, err := Load("testdata/minimal.yml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got, want := c.Run.Timeout, 30*time.Second; got != want {
		t.Errorf("Run.Timeout = %v, want %v", got, want)
	}
	if got, want := c.Run.MaxBytes, int64(1<<20); got != want {
		t.Errorf("Run.MaxBytes = %d, want %d", got, want)
	}
	if got, want := c.Trace.Timeout, 10*time.Second; got != want {
		t.Errorf("Trace.Timeout = %v, want %v", got, want)
	}
	if got, want := c.Trace.IdentityURL, "https://ifconfig.co/json"; got != want {
		t.Errorf("Trace.IdentityURL = %q, want %q", got, want)
	}
	if got, want := c.Wisp.Relay, "tunnel+wss://wisper.gost.run:443"; got != want {
		t.Errorf("Wisp.Relay = %q, want %q", got, want)
	}
	if got, want := c.Wisp.Domain, "gost.run"; got != want {
		t.Errorf("Wisp.Domain = %q, want %q", got, want)
	}
	if got, want := c.Wisp.MaxTTL, time.Hour; got != want {
		t.Errorf("Wisp.MaxTTL = %v, want %v", got, want)
	}
	if got, want := c.Wisp.MaxLeases, 4; got != want {
		t.Errorf("Wisp.MaxLeases = %d, want %d", got, want)
	}
	if got, want := c.Wisp.Allow, []string{"127.0.0.0/8", "::1/128"}; !equal(got, want) {
		t.Errorf("Wisp.Allow = %q, want %q", got, want)
	}
	if got, want := c.Log.Level, "info"; got != want {
		t.Errorf("Log.Level = %q, want %q", got, want)
	}
}

func TestLoadExplicitValues(t *testing.T) {
	c, err := Load("testdata/egress.yml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := c.Run.MaxBytes, int64(1<<20); got != want {
		t.Errorf("Run.MaxBytes = %d, want %d", got, want)
	}
	if got, want := len(c.Egress), 2; got != want {
		t.Fatalf("len(Egress) = %d, want %d", got, want)
	}
	if c.Egress[0].Name != "direct" || c.Egress[1].Name != "jp" {
		t.Fatalf("profile order = %q, want [direct jp]", []string{c.Egress[0].Name, c.Egress[1].Name})
	}
	if got := c.Egress[0].Chain; got == nil || len(got) != 0 {
		t.Fatalf("direct Chain = %#v, want a non-nil empty slice", got)
	}
}

func TestLoadSkipsInvalidProfilesWhenAsked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gost-mcp.yml")
	data := `
egress:
  - name: good
    description: "works"
    chain: ["socks5://proxy.example.com:1080"]
  - name: bad
    description: ""
    chain: []
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded, want the invalid profile to fail validation")
	}

	var warnings []string
	c, err := LoadWith(path, LoadOptions{
		SkipInvalid: true,
		Warnf: func(format string, args ...any) {
			warnings = append(warnings, format)
		},
	})
	if err != nil {
		t.Fatalf("LoadWith(SkipInvalid): %v", err)
	}
	if len(c.Egress) != 1 || c.Egress[0].Name != "good" {
		t.Fatalf("Egress = %q, want only the good profile", c.Egress[0].Name)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %d, want 1", len(warnings))
	}
}

func TestLoadSkipInvalidDoesNotHideFileErrors(t *testing.T) {
	_, err := LoadWith("testdata/unknown.yml", LoadOptions{SkipInvalid: true})
	if err == nil {
		t.Fatal("LoadWith succeeded, want a file-level error to survive --skip-invalid")
	}
}

func TestValidateRejectsBothChainAndHops(t *testing.T) {
	c := &Config{Egress: []EgressProfile{{
		Name:        "both",
		Description: "both set",
		Chain:       []string{"socks5://proxy.example.com:1080"},
		Hops:        []*xconfig.HopConfig{{Name: "hop-0"}},
	}}}

	if err := c.Validate(); err == nil {
		t.Fatal("Validate succeeded, want chain and hops to be mutually exclusive")
	}
}

func TestValidateRejectsBypass(t *testing.T) {
	hop := func(h *xconfig.HopConfig) EgressProfile {
		p := validProfile("jp")
		p.Chain = nil
		p.Hops = []*xconfig.HopConfig{h}
		return p
	}
	node := func(n *xconfig.NodeConfig) *xconfig.HopConfig {
		n.Name = "n0"
		return &xconfig.HopConfig{Name: "hop-0", Nodes: []*xconfig.NodeConfig{n}}
	}
	chain := func(uri string) EgressProfile {
		p := validProfile("jp")
		p.Chain = []string{uri}
		return p
	}

	tests := []struct {
		name    string
		profile EgressProfile
	}{
		{"hop.bypass", hop(&xconfig.HopConfig{Name: "hop-0", Bypass: "corp"})},
		{"hop.bypasses", hop(&xconfig.HopConfig{Name: "hop-0", Bypasses: []string{"corp"}})},
		{"hop.metadata.matcher", hop(&xconfig.HopConfig{Name: "hop-0", Metadata: map[string]any{"matcher": "Host(`a`)"}})},
		{"hop.metadata.uppercase bypass", hop(&xconfig.HopConfig{Name: "hop-0", Metadata: map[string]any{"BYPASS": "corp"}})},
		{"node.bypass", hop(node(&xconfig.NodeConfig{Bypass: "corp"}))},
		{"node.bypasses", hop(node(&xconfig.NodeConfig{Bypasses: []string{"corp"}}))},
		{"node.matcher", hop(node(&xconfig.NodeConfig{Matcher: &xconfig.NodeMatcherConfig{Rule: "Host(`a`)"}}))},
		{"node.filter", hop(node(&xconfig.NodeConfig{Filter: &xconfig.NodeFilterConfig{Host: "example.com"}}))},
		{"node.metadata.filter", hop(node(&xconfig.NodeConfig{Metadata: map[string]any{"filter": "x"}}))},
		{"node.metadata.uppercase filter", hop(node(&xconfig.NodeConfig{Metadata: map[string]any{"FiLtEr": "x"}}))},
		{"chain ?bypass=", chain("socks5://proxy.example.com:1080?bypass=corp")},
		{"chain ?BYPASS=", chain("socks5://proxy.example.com:1080?BYPASS=corp")},
		{"chain ?ByPass=", chain("socks5://proxy.example.com:1080?ByPass=corp")},
		{"chain ?bypasses=", chain("socks5://proxy.example.com:1080?bypasses=corp")},
		{"chain ?matcher=", chain("socks5://proxy.example.com:1080?matcher=Host(%60a%60)")},
		{"chain ?filter=", chain("socks5://proxy.example.com:1080?filter=x")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Egress: []EgressProfile{tt.profile}}
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate succeeded for %s, want a rejection", tt.name)
			}
		})
	}
}

func TestValidateRejectsBadNames(t *testing.T) {
	tests := []struct {
		name     string
		profiles []EgressProfile
	}{
		{"empty", []EgressProfile{validProfile("")}},
		{"uppercase", []EgressProfile{validProfile("JP")}},
		{"space", []EgressProfile{validProfile("a b")}},
		{"too long", []EgressProfile{validProfile(strings.Repeat("a", 33))}},
		{"dot", []EgressProfile{validProfile("jp.tokyo")}},
		{"duplicate", []EgressProfile{validProfile("jp"), validProfile("jp")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Egress: tt.profiles}
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate succeeded for name %s, want a rejection", tt.name)
			}
		})
	}
}

func TestValidateRequiresOneEgress(t *testing.T) {
	if err := (&Config{}).Validate(); err == nil {
		t.Fatal("Validate succeeded, want an error when no egress profile is configured")
	}
}

func TestValidateRequiresChainOrHops(t *testing.T) {
	c := &Config{Egress: []EgressProfile{{
		Name:        "empty",
		Description: "neither chain nor hops",
	}}}
	if err := c.Validate(); err == nil {
		t.Fatal("Validate succeeded, want an error when chain and hops are both omitted")
	}
}

func TestValidateAcceptsDirectAndHops(t *testing.T) {
	c := &Config{Egress: []EgressProfile{
		{Name: "direct", Description: "no proxy", Chain: []string{}},
		{
			Name:        "corp",
			Description: "two hops",
			Hops: []*xconfig.HopConfig{
				{Name: "hop-0", Nodes: []*xconfig.NodeConfig{{Name: "a", Addr: "http://10.0.0.1:8080"}}},
				{Name: "hop-1", Nodes: []*xconfig.NodeConfig{{Name: "b", Addr: "socks5://10.0.1.5:1080"}}},
			},
		},
		{Name: "jp_1", Description: "sugar", Chain: []string{"socks5://tokyo.example.com:1080?interface=wlan0"}},
	}}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateWispBounds(t *testing.T) {
	base := func() *Config {
		return &Config{Egress: []EgressProfile{{Name: "direct", Description: "no proxy", Chain: []string{}}}}
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"relay without scheme", func(c *Config) { c.Wisp.Relay = "wisper.gost.run:443" }},
		{"empty domain", func(c *Config) { c.Wisp.Domain = " " }},
		{"negative ttl", func(c *Config) { c.Wisp.MaxTTL = -time.Second }},
		{"ttl too large", func(c *Config) { c.Wisp.MaxTTL = 48 * time.Hour }},
		{"no leases", func(c *Config) { c.Wisp.MaxLeases = -1 }},
		{"leases too many", func(c *Config) { c.Wisp.MaxLeases = 1000 }},
		{"bad allow entry", func(c *Config) { c.Wisp.Allow = []string{"not-a-cidr"} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate succeeded for %s, want a rejection", tt.name)
			}
		})
	}
}

func TestChainConfigFromSugar(t *testing.T) {
	p := EgressProfile{
		Name:        "jp",
		Description: "two proxies",
		Chain:       []string{"socks5://h:1080", "http://h:8080"},
	}

	cfg, err := p.ChainConfig()
	if err != nil {
		t.Fatalf("ChainConfig: %v", err)
	}
	if cfg.Name != "jp" {
		t.Errorf("Name = %q, want %q", cfg.Name, "jp")
	}
	// gost's -F sugar is sequential: each URI is a hop.
	if len(cfg.Hops) != 2 {
		t.Fatalf("len(Hops) = %d, want 2", len(cfg.Hops))
	}
	var nodes int
	for _, h := range cfg.Hops {
		nodes += len(h.Nodes)
	}
	if nodes != 2 {
		t.Errorf("node count = %d, want 2", nodes)
	}
}

func TestChainConfigDirect(t *testing.T) {
	p := EgressProfile{Name: "direct", Description: "no proxy", Chain: []string{}}

	cfg, err := p.ChainConfig()
	if err != nil {
		t.Fatalf("ChainConfig: %v", err)
	}
	if cfg.Name != "direct" {
		t.Errorf("Name = %q, want direct", cfg.Name)
	}
	if len(cfg.Hops) != 0 {
		t.Errorf("len(Hops) = %d, want 0", len(cfg.Hops))
	}
}

func TestChainConfigHops(t *testing.T) {
	hops := []*xconfig.HopConfig{
		{Name: "hop-0", Nodes: []*xconfig.NodeConfig{{Name: "a", Addr: "http://10.0.0.1:8080"}}},
	}
	p := EgressProfile{Name: "corp", Description: "explicit hops", Hops: hops}

	cfg, err := p.ChainConfig()
	if err != nil {
		t.Fatalf("ChainConfig: %v", err)
	}
	if cfg.Name != "corp" || len(cfg.Hops) != 1 || cfg.Hops[0].Name != "hop-0" {
		t.Fatalf("ChainConfig = %+v, want the hop configs preserved", cfg)
	}
}

func TestChainConfigWithoutChainOrHopsIsError(t *testing.T) {
	p := EgressProfile{Name: "broken", Description: "nothing"}
	if _, err := p.ChainConfig(); err == nil {
		t.Fatal("ChainConfig succeeded, want an error")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
