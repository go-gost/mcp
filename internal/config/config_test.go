package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xconfig "github.com/go-gost/x/config"
	"gopkg.in/yaml.v3"
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

// TestLoadExpandsOnlyScalarValues pins that ${...} in a comment is not
// expanded, and that a substituted value with YAML metacharacters lands intact
// after parsing.
func TestLoadExpandsOnlyScalarValues(t *testing.T) {
	t.Setenv("WEIRD_PASS", `p"a#s:s`)
	t.Setenv("JP_USER", "alice")

	path := filepath.Join(t.TempDir(), "gost-mcp.yml")
	data := `
# This comment mentions ${NOT_A_REAL_VARIABLE} and must not be expanded.
# A key named ${KEY} is not a value either.
egress:
  - name: jp
    description: "exit for ${JP_USER} using ${WEIRD_PASS}"
    chain:
      - "socks5://${JP_USER}@host:1080"
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Egress) != 1 {
		t.Fatalf("len(Egress) = %d, want 1", len(c.Egress))
	}
	// The substituted value contains a quote, a hash, and a colon. Expanding
	// the raw bytes would have closed the YAML string early and turned the
	// rest into a comment.
	if got, want := c.Egress[0].Description, `exit for alice using p"a#s:s`; got != want {
		t.Errorf("Description = %q, want %q", got, want)
	}
	if got, want := c.Egress[0].Chain[0], "socks5://alice@host:1080"; got != want {
		t.Errorf("Chain[0] = %q, want %q", got, want)
	}
}

// TestExpandEnvKeepsPasswordIntact pins the value-level substitution directly:
// a password containing a quote, hash, and colon survives the round trip into a
// valid YAML document.
func TestExpandEnvKeepsPasswordIntact(t *testing.T) {
	t.Setenv("PASS", `p"a#s:s`)
	out, err := expandEnv([]byte(`
egress:
  - chain:
      - "socks5://u:${PASS}@host:1080"
`))
	if err != nil {
		t.Fatalf("expandEnv: %v", err)
	}

	var doc struct {
		Egress []struct {
			Chain []string `yaml:"chain"`
		} `yaml:"egress"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("expanded YAML does not parse: %v\n%s", err, out)
	}
	if got, want := doc.Egress[0].Chain[0], `socks5://u:p"a#s:s@host:1080`; got != want {
		t.Errorf("chain = %q, want %q", got, want)
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

// TestValidateRejectsDroppedNamedComponents covers chain query parameters
// that ChainConfig drops (they become file-level resolvers/hosts, which an
// egress-only profile cannot carry), so accepting them would silently resolve
// to nothing.
func TestValidateRejectsDroppedNamedComponents(t *testing.T) {
	chain := func(uri string) EgressProfile {
		p := validProfile("jp")
		p.Chain = []string{uri}
		return p
	}

	tests := []struct {
		name string
		uri  string
	}{
		{"resolver", "socks5://proxy.example.com:1080?resolver=r1"},
		{"hosts", "socks5://proxy.example.com:1080?hosts=h1"},
		{"sd", "socks5://proxy.example.com:1080?sd=s1"},
		{"uppercase resolver", "socks5://proxy.example.com:1080?RESOLVER=r1"},
		{"node-prefixed resolver", "socks5://proxy.example.com:1080?node.resolver=r1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Egress: []EgressProfile{chain(tt.uri)}}
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate succeeded for %s, want a rejection", tt.name)
			}
		})
	}
}

// TestValidateRejectsEmptyHop pins the static cause of a truncated chain:
// gost stops at a hop that selects no node, so a zero-node hop would let
// traffic leave through the previous hop (or dial directly for hop 0).
func TestValidateRejectsEmptyHop(t *testing.T) {
	tests := []struct {
		name string
		hops []*xconfig.HopConfig
	}{
		{"no nodes field", []*xconfig.HopConfig{{Name: "hop-0"}}},
		{"empty nodes", []*xconfig.HopConfig{{Name: "hop-0", Nodes: []*xconfig.NodeConfig{}}}},
		{"second hop empty", []*xconfig.HopConfig{
			{Name: "hop-0", Nodes: []*xconfig.NodeConfig{hopNode("a")}},
			{Name: "hop-1"},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Egress: []EgressProfile{hopsProfile(tt.hops...)}}
			err := c.Validate()
			if err == nil {
				t.Fatalf("Validate succeeded for %s, want a rejection", tt.name)
			}
			if !strings.Contains(err.Error(), "node") {
				t.Fatalf("error = %v, want it to mention the missing node", err)
			}
		})
	}
}

// TestValidateRejectsDynamicHopSource rejects hops whose node set can change
// (or become empty) after startup: static validation cannot vouch for them.
func TestValidateRejectsDynamicHopSource(t *testing.T) {
	newHop := func() *xconfig.HopConfig {
		return &xconfig.HopConfig{Name: "hop-0", Nodes: []*xconfig.NodeConfig{hopNode("n0")}}
	}

	tests := []struct {
		name   string
		mutate func(*xconfig.HopConfig)
	}{
		{"file", func(h *xconfig.HopConfig) { h.File = &xconfig.FileLoader{Path: "hops.json"} }},
		{"redis", func(h *xconfig.HopConfig) { h.Redis = &xconfig.RedisLoader{Addr: "127.0.0.1:6379"} }},
		{"http", func(h *xconfig.HopConfig) { h.HTTP = &xconfig.HTTPLoader{URL: "http://127.0.0.1:8000/hops"} }},
		{"plugin", func(h *xconfig.HopConfig) { h.Plugin = &xconfig.PluginConfig{Addr: "127.0.0.1:8001"} }},
		{"reload", func(h *xconfig.HopConfig) { h.Reload = time.Second }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHop()
			tt.mutate(h)
			c := &Config{Egress: []EgressProfile{hopsProfile(h)}}
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate succeeded for %s, want a rejection", tt.name)
			}
		})
	}
}

// TestValidateRejectsDuplicateNodeName requires stable, unique node names:
// they are the served_by contract used to attribute an exit to a node.
func TestValidateRejectsDuplicateNodeName(t *testing.T) {
	tests := []struct {
		name string
		hops []*xconfig.HopConfig
	}{
		{"empty name", []*xconfig.HopConfig{{Name: "hop-0", Nodes: []*xconfig.NodeConfig{{Addr: "http://10.0.0.1:8080"}}}}},
		{"blank name", []*xconfig.HopConfig{{Name: "hop-0", Nodes: []*xconfig.NodeConfig{{Name: " ", Addr: "http://10.0.0.1:8080"}}}}},
		{"duplicate in one hop", []*xconfig.HopConfig{{Name: "hop-0", Nodes: []*xconfig.NodeConfig{hopNode("a"), hopNode("a")}}}},
		{"duplicate across hops", []*xconfig.HopConfig{
			{Name: "hop-0", Nodes: []*xconfig.NodeConfig{hopNode("a")}},
			{Name: "hop-1", Nodes: []*xconfig.NodeConfig{hopNode("a")}},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Egress: []EgressProfile{hopsProfile(tt.hops...)}}
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate succeeded for %s, want a rejection", tt.name)
			}
		})
	}
}

// TestValidateRejectsNamedResolution covers hop- and node-level resolver/hosts:
// the named components are never built, so accepting them would silently fall
// back to system resolution.
func TestValidateRejectsNamedResolution(t *testing.T) {
	tests := []struct {
		name string
		hop  *xconfig.HopConfig
	}{
		{"hop.resolver", &xconfig.HopConfig{Name: "hop-0", Resolver: "r1", Nodes: []*xconfig.NodeConfig{hopNode("n0")}}},
		{"hop.hosts", &xconfig.HopConfig{Name: "hop-0", Hosts: "h1", Nodes: []*xconfig.NodeConfig{hopNode("n0")}}},
		{"node.resolver", &xconfig.HopConfig{Name: "hop-0", Nodes: []*xconfig.NodeConfig{{Name: "n0", Addr: "http://10.0.0.1:8080", Resolver: "r1"}}}},
		{"node.hosts", &xconfig.HopConfig{Name: "hop-0", Nodes: []*xconfig.NodeConfig{{Name: "n0", Addr: "http://10.0.0.1:8080", Hosts: "h1"}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Egress: []EgressProfile{hopsProfile(tt.hop)}}
			if err := c.Validate(); err == nil {
				t.Fatalf("Validate succeeded for %s, want a rejection", tt.name)
			}
		})
	}
}

// TestValidateRejectsNodeProbe rejects gost's active node probing: an egress
// profile must not generate traffic unrelated to a tool call.
func TestValidateRejectsNodeProbe(t *testing.T) {
	hop := &xconfig.HopConfig{Name: "hop-0", Nodes: []*xconfig.NodeConfig{{
		Name:  "n0",
		Addr:  "10.0.0.1:8080",
		Probe: &xconfig.ProbeConfig{},
	}}}
	c := &Config{Egress: []EgressProfile{hopsProfile(hop)}}
	if err := c.Validate(); err == nil {
		t.Fatal("Validate succeeded, want node.probe to be rejected")
	}
}

// hopNode returns a minimally valid, uniquely named node for validation tests.
func hopNode(name string) *xconfig.NodeConfig {
	return &xconfig.NodeConfig{Name: name, Addr: "http://10.0.0.1:8080"}
}

// hopsProfile returns an explicit-hops profile, overriding validProfile's sugar
// chain.
func hopsProfile(hops ...*xconfig.HopConfig) EgressProfile {
	p := validProfile("corp")
	p.Chain = nil
	p.Hops = hops
	return p
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
	seen := make(map[string]bool)
	for _, h := range cfg.Hops {
		nodes += len(h.Nodes)
		for _, n := range h.Nodes {
			if n.Name == "" {
				t.Errorf("node without a name in hop %q", h.Name)
				continue
			}
			if seen[n.Name] {
				t.Errorf("duplicate node name %q across hops", n.Name)
			}
			seen[n.Name] = true
		}
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
