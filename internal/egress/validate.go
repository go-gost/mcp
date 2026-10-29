package egress

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-gost/mcp/internal/config"
	xconfig "github.com/go-gost/x/config"
	"github.com/go-gost/x/registry"
)

// validateConnections rejects a profile whose nodes would not actually use the
// configured connector.
//
// gost's command parser falls back to the HTTP connector for any unregistered
// scheme, so grpc:// or socks5h:// would silently become an HTTP proxy. A
// direct/virtual connector would likewise skip the hop. Both are checked after
// ChainConfig so the raw URI is still available.
func validateConnections(p *config.EgressProfile, cfg *xconfig.ChainConfig) error {
	if p.Chain != nil {
		for i, raw := range p.Chain {
			if err := validateChainScheme(p.Name, i, raw); err != nil {
				return err
			}
		}
	}
	for hi, hop := range cfg.Hops {
		if hop == nil {
			continue
		}
		for ni, node := range hop.Nodes {
			if err := validateNode(p.Name, hi, ni, node); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateChainScheme requires every component of a sugar chain URI to name a
// registered gost connector or dialer.
func validateChainScheme(profile string, index int, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("egress %q: chain[%d]: must be a node URI such as socks5://host:1080", profile, index)
	}
	scheme := u.Scheme
	if scheme == "https" {
		// gost normalizes https to http+tls before resolving the scheme.
		scheme = "http+tls"
	}
	for _, part := range strings.Split(scheme, "+") {
		if registry.ConnectorRegistry().Get(part) == nil && registry.DialerRegistry().Get(part) == nil {
			return fmt.Errorf("egress %q: chain[%d]: unsupported protocol %q", profile, index, u.Scheme)
		}
	}
	return nil
}

// validateNode checks one node after ChainConfig.
//
// Explicit hops describe a proxy with connector.type; embedding the protocol in
// addr (socks5://host:1080) makes gost's fallback invisible and is rejected.
// A direct or virtual connector is rejected because it skips the egress.
func validateNode(profile string, hopIndex, nodeIndex int, node *xconfig.NodeConfig) error {
	where := fmt.Sprintf("egress %q: hops[%d].nodes[%d]", profile, hopIndex, nodeIndex)
	if node == nil {
		return fmt.Errorf("%s: empty node", where)
	}

	addr := strings.TrimSpace(node.Addr)
	if addr == "" {
		return fmt.Errorf("%s: addr is required", where)
	}
	if strings.Contains(addr, "://") {
		return fmt.Errorf("%s: addr must be host:port without a scheme; set connector.type instead", where)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("%s: addr must be host:port", where)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%s: addr port must be an integer in 1..65535", where)
	}

	if node.Probe != nil {
		return fmt.Errorf("%s: probe is not allowed in an egress profile", where)
	}

	connector := "http" // gost's default when connector.type is omitted
	if node.Connector != nil {
		if t := strings.ToLower(strings.TrimSpace(node.Connector.Type)); t != "" {
			connector = t
		}
	}
	switch connector {
	case "direct", "virtual":
		return fmt.Errorf("%s: connector.type %q would bypass the egress", where, connector)
	}
	if registry.ConnectorRegistry().Get(connector) == nil {
		return fmt.Errorf("%s: unsupported connector.type %q", where, connector)
	}
	return nil
}
