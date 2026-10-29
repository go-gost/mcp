package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	xconfig "github.com/go-gost/x/config"
)

var namePattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// forbiddenKeys make gost skip a hop, and skipping the last hop means a direct
// dial. In an egress-only tool that is a hidden bypass, so they are rejected.
var forbiddenKeys = []string{"bypass", "bypasses", "matcher", "filter"}

// forbiddenChainParams are named components that BuildConfigFromCmd turns into
// file-level resolvers/hosts. This config has no place for them, so a chain URI
// asking for one would silently resolve to nothing; rejecting it is clearer.
var forbiddenChainParams = []string{"resolver", "hosts", "sd"}

// Validate checks the whole file: file-level settings and every profile.
func (c *Config) Validate() error {
	if err := c.validateFile(); err != nil {
		return err
	}
	if len(c.Egress) == 0 {
		return errors.New("config: at least one egress profile is required")
	}
	seen := make(map[string]bool, len(c.Egress))
	for i := range c.Egress {
		if err := validateProfile(&c.Egress[i], seen); err != nil {
			return err
		}
	}
	return nil
}

// validateFile checks settings that are not tied to a single profile. These
// errors are never skipped by --skip-invalid.
func (c *Config) validateFile() error {
	if err := c.Wisp.validate(); err != nil {
		return err
	}
	if err := c.Log.validate(); err != nil {
		return err
	}
	return nil
}

func (w *WispConfig) validate() error {
	if w.Relay != "" {
		u, err := url.Parse(w.Relay)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return errors.New("config: gost_wisp.relay: must be a URL such as tunnel+wss://relay.example.com:443")
		}
	}
	if w.Domain != "" {
		d := strings.TrimSpace(w.Domain)
		if d == "" {
			return errors.New("config: gost_wisp.domain: must not be blank")
		}
		for _, r := range d {
			if unicode.IsSpace(r) || r == '/' || r == ':' || r == '\\' {
				return fmt.Errorf("config: gost_wisp.domain: %q is not a domain name", w.Domain)
			}
		}
	}
	if w.MaxTTL != 0 && (w.MaxTTL < time.Second || w.MaxTTL > 24*time.Hour) {
		return fmt.Errorf("config: gost_wisp.max_ttl: %v is outside the allowed range 1s..24h", w.MaxTTL)
	}
	if w.MaxLeases != 0 && (w.MaxLeases < 1 || w.MaxLeases > 64) {
		return fmt.Errorf("config: gost_wisp.max_leases: %d is outside the allowed range 1..64", w.MaxLeases)
	}
	for _, a := range w.Allow {
		if !validHostOrPrefix(a) {
			return fmt.Errorf("config: gost_wisp.allow: %q is not an IP address or CIDR prefix", a)
		}
	}
	return nil
}

func validHostOrPrefix(s string) bool {
	s = strings.TrimSpace(s)
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return false
}

func (l *LogConfig) validate() error {
	switch l.Level {
	case "", "debug", "info", "warn", "error":
		return nil
	}
	return fmt.Errorf("config: log.level: %q is not one of debug, info, warn, error", l.Level)
}

// validateProfile validates one profile. seen accumulates names of profiles
// that already passed, so a duplicate can be reported (or skipped) without
// hiding the first one.
func validateProfile(p *EgressProfile, seen map[string]bool) error {
	if p == nil {
		return errors.New("config: egress: empty profile")
	}
	if !namePattern.MatchString(p.Name) {
		return fmt.Errorf("config: egress: invalid profile name %q (want %s)", p.Name, namePattern)
	}
	if seen != nil && seen[p.Name] {
		return fmt.Errorf("config: egress %q: duplicate profile name", p.Name)
	}
	if strings.TrimSpace(p.Description) == "" {
		return fmt.Errorf("config: egress %q: description is required", p.Name)
	}

	// A non-nil empty slice is an explicit `chain: []` (the direct profile);
	// nil means the key was omitted.
	hasChain, hasHops := p.Chain != nil, p.Hops != nil
	switch {
	case hasChain && hasHops:
		return fmt.Errorf("config: egress %q: chain and hops are mutually exclusive", p.Name)
	case !hasChain && !hasHops:
		return fmt.Errorf("config: egress %q: exactly one of chain or hops is required", p.Name)
	case hasHops && len(p.Hops) == 0:
		return fmt.Errorf("config: egress %q: hops must not be empty", p.Name)
	}

	if hasChain {
		if err := validateChain(p.Name, p.Chain); err != nil {
			return err
		}
	} else {
		for i, hop := range p.Hops {
			if err := validateHop(p.Name, i, hop); err != nil {
				return err
			}
		}
	}

	if seen != nil {
		seen[p.Name] = true
	}
	return nil
}

// validateChain checks each -F style URI. URIs are never echoed in errors:
// they routinely carry credentials.
func validateChain(profile string, chain []string) error {
	for i, raw := range chain {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("config: egress %q: chain[%d]: must be a node URI such as socks5://host:1080", profile, i)
		}
		q := u.Query()
		for key := range q {
			if isForbiddenKey(key) {
				return fmt.Errorf("config: egress %q: chain[%d]: query parameter %q is not allowed in an egress profile", profile, i, key)
			}
			if isForbiddenChainParam(key) {
				return fmt.Errorf("config: egress %q: chain[%d]: query parameter %q cannot be carried by an egress profile", profile, i, key)
			}
		}
	}
	return nil
}

func validateHop(profile string, index int, hop *xconfig.HopConfig) error {
	where := fmt.Sprintf("config: egress %q: hops[%d]", profile, index)
	if hop == nil {
		return fmt.Errorf("%s: empty hop", where)
	}
	if hop.Bypass != "" || len(hop.Bypasses) > 0 {
		return fmt.Errorf("%s: bypass is not allowed (it can skip the hop and dial direct)", where)
	}
	if err := rejectMetadata(where, hop.Metadata); err != nil {
		return err
	}
	for j, node := range hop.Nodes {
		if node == nil {
			return fmt.Errorf("%s: nodes[%d]: empty node", where, j)
		}
		nwhere := fmt.Sprintf("%s: nodes[%d]", where, j)
		if node.Bypass != "" || len(node.Bypasses) > 0 {
			return fmt.Errorf("%s: bypass is not allowed (it can skip the hop and dial direct)", nwhere)
		}
		if node.Matcher != nil {
			return fmt.Errorf("%s: matcher is not allowed in an egress profile", nwhere)
		}
		if node.Filter != nil {
			return fmt.Errorf("%s: filter is not allowed in an egress profile", nwhere)
		}
		if err := rejectMetadata(nwhere, node.Metadata); err != nil {
			return err
		}
	}
	return nil
}

func rejectMetadata(where string, md map[string]any) error {
	for key := range md {
		if isForbiddenKey(key) {
			return fmt.Errorf("%s: metadata %q is not allowed in an egress profile", where, key)
		}
	}
	return nil
}

func isForbiddenKey(key string) bool {
	key = normalizeKey(key)
	for _, k := range forbiddenKeys {
		if key == k {
			return true
		}
	}
	return false
}

func isForbiddenChainParam(key string) bool {
	key = normalizeKey(key)
	for _, k := range forbiddenChainParams {
		if key == k {
			return true
		}
	}
	return false
}

// normalizeKey lowercases and strips the hop./node. prefixes: gost lowercases
// metadata keys before reading them (mdx.NewMetadata), so the checks must be
// case-insensitive or ?BYPASS=xx would slip through.
func normalizeKey(key string) string {
	key = strings.ToLower(key)
	return strings.TrimPrefix(strings.TrimPrefix(key, "hop."), "node.")
}
