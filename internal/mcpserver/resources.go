package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-gost/x/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// egressResourceURI is the resource the model reads to discover profiles.
const egressResourceURI = "gost-mcp://egress"

// egressResource is one profile as the model sees it. Node addresses are only
// present with --expose-topology; the default payload is name + description.
type egressResource struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Nodes       []egressNode `json:"nodes,omitempty"`
}

// egressNode is one node address in an exposed topology. It carries no
// credentials: gost keeps authentication in the connector config.
type egressNode struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// addEgressResource registers gost-mcp://egress.
func addEgressResource(srv *mcp.Server, s *server) {
	srv.AddResource(&mcp.Resource{
		URI:         egressResourceURI,
		Name:        "egress",
		Description: "Configured egress profiles. Each entry has a name and a description; pass the name to gost_run or gost_trace. Node addresses are shown only when the server was started with --expose-topology.",
		MIMEType:    "application/json",
	}, s.readEgressResource)
}

// readEgressResource renders every profile in declaration order.
func (s *server) readEgressResource(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	profiles := s.deps.Egress.Profiles()
	out := make([]egressResource, 0, len(profiles))
	for _, p := range profiles {
		r := egressResource{Name: p.Name, Description: p.Description}
		if s.deps.ExposeTopology {
			if e, ok := s.deps.Egress.Get(p.Name); ok {
				r.Nodes = nodeResources(e.HopConfigs())
			}
		}
		out = append(out, r)
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", egressResourceURI, err)
	}

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      egressResourceURI,
			MIMEType: "application/json",
			Text:     string(data),
		}},
	}, nil
}

// nodeResources flattens hop configs into name/address pairs, stripping any
// userinfo so a topology dump can never leak a credential.
func nodeResources(hops []*config.HopConfig) []egressNode {
	var out []egressNode
	for _, hop := range hops {
		if hop == nil {
			continue
		}
		for _, node := range hop.Nodes {
			if node == nil || node.Addr == "" {
				continue
			}
			out = append(out, egressNode{Name: node.Name, Addr: stripUserInfo(node.Addr)})
		}
	}
	return out
}

// stripUserInfo removes credentials from an address when one is embedded.
//
// A scheme-qualified address (socks5://user:pass@host:1080) parses with a User
// and is rebuilt without it. A scheme-less address (user:pass@host:1080) parses
// as the scheme "user" with an opaque part, so User is nil and the string would
// otherwise pass through untouched; for those the authority is scanned for the
// last "@" instead. Only the authority is considered, so an "@" inside a path
// or query is left alone.
func stripUserInfo(addr string) string {
	if u, err := url.Parse(addr); err == nil && u.User != nil {
		u.User = nil
		return u.String()
	}

	rest := addr
	if i := strings.Index(addr, "://"); i >= 0 {
		rest = addr[i+3:]
	}
	authority, tail := rest, ""
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		authority, tail = rest[:j], rest[j:]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		return authority[at+1:] + tail
	}
	return addr
}
