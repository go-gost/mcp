package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// envRefPattern matches ${NAME} references. Only the braced form is expanded:
// a bare "$" is common in credentials and must survive untouched.
var envRefPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// LoadOptions controls LoadWith.
type LoadOptions struct {
	// SkipInvalid drops egress profiles that fail validation instead of
	// failing the whole load. File-level errors are never skipped.
	SkipInvalid bool
	// Warnf receives one message per skipped profile. A nil function
	// discards the warnings.
	Warnf func(format string, args ...any)
}

// Load reads, expands, decodes, default-applies, and validates the
// configuration at path. An empty path searches ./gost-mcp.yml,
// ~/.gost-mcp/gost-mcp.yml, then /etc/gost-mcp/gost-mcp.yml.
func Load(path string) (*Config, error) {
	return LoadWith(path, LoadOptions{})
}

// LoadWith is Load with per-profile skip semantics for --skip-invalid.
func LoadWith(path string, opts LoadOptions) (*Config, error) {
	c, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	if !opts.SkipInvalid {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		return c, nil
	}

	if err := c.validateFile(); err != nil {
		return nil, err
	}
	warnf := opts.Warnf
	if warnf == nil {
		warnf = func(string, ...any) {}
	}
	seen := make(map[string]bool, len(c.Egress))
	kept := c.Egress[:0]
	for _, p := range c.Egress {
		if err := validateProfile(&p, seen); err != nil {
			warnf("skipping egress profile: %v", err)
			continue
		}
		kept = append(kept, p)
	}
	c.Egress = kept
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// ResolvePath returns the file Load would read for path.
func ResolvePath(path string) (string, error) {
	if path != "" {
		fi, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("config: %w", err)
		}
		if fi.IsDir() {
			return "", fmt.Errorf("config: %s is a directory", path)
		}
		return path, nil
	}

	candidates := defaultPaths()
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("config: no configuration file found (looked in %s)", strings.Join(candidates, ", "))
}

func defaultPaths() []string {
	paths := []string{"gost-mcp.yml"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".gost-mcp", "gost-mcp.yml"))
	}
	return append(paths, filepath.Join(string(filepath.Separator), "etc", "gost-mcp", "gost-mcp.yml"))
}

func loadFile(path string) (*Config, error) {
	resolved, err := ResolvePath(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	data, err = expandEnv(data)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", resolved, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config: %s is empty", resolved)
		}
		return nil, fmt.Errorf("config: %s: %w", resolved, err)
	}
	var extra any
	switch err := dec.Decode(&extra); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return nil, fmt.Errorf("config: %s: %w", resolved, err)
	case extra != nil:
		return nil, fmt.Errorf("config: %s: multiple YAML documents are not supported", resolved)
	}

	c.applyDefaults()
	return &c, nil
}

// expandEnv replaces ${NAME} in scalar string values after YAML parsing.
//
// Expanding the raw bytes would also rewrite comments and mapping keys, and an
// expanded value containing YAML metacharacters (":", "#", quotes) could change
// the document's structure. Walking the node tree keeps comments and keys
// untouched and lets the marshaller quote the substituted value correctly.
// Every reference must resolve: an unset variable is an error, never an empty
// string, so a missing credential cannot silently turn into an anonymous
// connection.
func expandEnv(data []byte) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return data, nil
		}
		return nil, err
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return nil, err
	case extra.Content != nil:
		return nil, errors.New("multiple YAML documents are not supported")
	}

	var missing []string
	seen := make(map[string]bool)
	expand := func(s string) string {
		return envRefPattern.ReplaceAllStringFunc(s, func(m string) string {
			name := m[2 : len(m)-1]
			v, ok := os.LookupEnv(name)
			if !ok {
				if !seen[name] {
					seen[name] = true
					missing = append(missing, name)
				}
				return m
			}
			return v
		})
	}
	expandNode(&doc, expand)

	if len(missing) > 0 {
		return nil, fmt.Errorf("undefined environment variable(s): %s", strings.Join(missing, ", "))
	}
	return yaml.Marshal(&doc)
}

// expandNode applies expand to string scalar values only. Mapping keys and
// comments are not scalar values here, so neither is rewritten.
func expandNode(node *yaml.Node, expand func(string) string) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			expandNode(child, expand)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			expandNode(node.Content[i+1], expand)
		}
	case yaml.AliasNode:
		expandNode(node.Alias, expand)
	case yaml.ScalarNode:
		if node.Tag == "!!str" {
			node.Value = expand(node.Value)
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Run.Timeout <= 0 {
		c.Run.Timeout = DefaultRunTimeout
	}
	if c.Run.MaxBytes <= 0 {
		c.Run.MaxBytes = DefaultRunMaxBytes
	}
	if c.Trace.Timeout <= 0 {
		c.Trace.Timeout = DefaultTraceTimeout
	}
	if c.Trace.IdentityURL == "" {
		c.Trace.IdentityURL = DefaultTraceIdentityURL
	}
	if c.Wisp.Relay == "" {
		c.Wisp.Relay = DefaultWispRelay
	}
	if c.Wisp.Domain == "" {
		c.Wisp.Domain = DefaultWispDomain
	}
	if c.Wisp.MaxTTL <= 0 {
		c.Wisp.MaxTTL = DefaultWispMaxTTL
	}
	if c.Wisp.MaxLeases <= 0 {
		c.Wisp.MaxLeases = DefaultWispMaxLeases
	}
	if len(c.Wisp.Allow) == 0 {
		c.Wisp.Allow = append([]string(nil), DefaultWispAllow...)
	}
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	if c.Log.Level == "" {
		c.Log.Level = DefaultLogLevel
	}
}

// The sections below accept Go duration strings ("30s") and sizes ("1MiB").
// yaml.v3 does not do that natively, and a custom UnmarshalYAML method bypasses
// the decoder's KnownFields setting, so each section rejects unknown keys
// itself.

func (c *RunConfig) UnmarshalYAML(node *yaml.Node) error {
	if err := sectionKeys(node, "RunConfig", "timeout", "max_bytes"); err != nil {
		return err
	}
	var raw struct {
		Timeout  any `yaml:"timeout"`
		MaxBytes any `yaml:"max_bytes"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	var err error
	if c.Timeout, err = durationValue(raw.Timeout, "gost_run.timeout"); err != nil {
		return err
	}
	if c.MaxBytes, err = byteValue(raw.MaxBytes, "gost_run.max_bytes"); err != nil {
		return err
	}
	return nil
}

func (c *TraceConfig) UnmarshalYAML(node *yaml.Node) error {
	if err := sectionKeys(node, "TraceConfig", "timeout", "identity_url"); err != nil {
		return err
	}
	var raw struct {
		Timeout     any    `yaml:"timeout"`
		IdentityURL string `yaml:"identity_url"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	var err error
	if c.Timeout, err = durationValue(raw.Timeout, "gost_trace.timeout"); err != nil {
		return err
	}
	c.IdentityURL = raw.IdentityURL
	return nil
}

func (c *WispConfig) UnmarshalYAML(node *yaml.Node) error {
	if err := sectionKeys(node, "WispConfig", "relay", "domain", "max_ttl", "max_leases", "allow"); err != nil {
		return err
	}
	var raw struct {
		Relay     string   `yaml:"relay"`
		Domain    string   `yaml:"domain"`
		MaxTTL    any      `yaml:"max_ttl"`
		MaxLeases int      `yaml:"max_leases"`
		Allow     []string `yaml:"allow"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	var err error
	if c.MaxTTL, err = durationValue(raw.MaxTTL, "gost_wisp.max_ttl"); err != nil {
		return err
	}
	c.Relay = raw.Relay
	c.Domain = raw.Domain
	c.MaxLeases = raw.MaxLeases
	c.Allow = raw.Allow
	return nil
}

func sectionKeys(node *yaml.Node, section string, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("config: %s must be a mapping", section)
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		ok := false
		for _, a := range allowed {
			if key == a {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("config: field %s not found in type config.%s", key, section)
		}
	}
	return nil
}

// durationValue accepts "30s" or a bare number of seconds.
func durationValue(v any, field string) (time.Duration, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(x))
		if err != nil {
			return 0, fmt.Errorf("config: %s: %w", field, err)
		}
		return d, nil
	case int:
		return time.Duration(x) * time.Second, nil
	case int64:
		return time.Duration(x) * time.Second, nil
	case float64:
		return time.Duration(x * float64(time.Second)), nil
	default:
		return 0, fmt.Errorf("config: %s: invalid duration %v", field, v)
	}
}

// byteValue accepts a byte count or a size string such as "1MiB".
func byteValue(v any, field string) (int64, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case uint64:
		if x > math.MaxInt64 {
			return 0, fmt.Errorf("config: %s: size overflows int64", field)
		}
		return int64(x), nil
	case float64:
		if x != math.Trunc(x) {
			return 0, fmt.Errorf("config: %s: size must be an integer", field)
		}
		return int64(x), nil
	case string:
		n, err := parseSize(x)
		if err != nil {
			return 0, fmt.Errorf("config: %s: %w", field, err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("config: %s: invalid size %v", field, v)
	}
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	n, err := strconv.ParseInt(s[:end], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	var mult int64 = 1
	switch strings.ToUpper(strings.TrimSpace(s[end:])) {
	case "", "B":
	case "K", "KB", "KIB":
		mult = 1 << 10
	case "M", "MB", "MIB":
		mult = 1 << 20
	case "G", "GB", "GIB":
		mult = 1 << 30
	default:
		return 0, fmt.Errorf("invalid size %q", s)
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("size %q overflows int64", s)
	}
	return n * mult, nil
}
