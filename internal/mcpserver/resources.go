package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-gost/x/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// egressResourceURI is the resource the model reads to discover profiles.
const egressResourceURI = "gost-mcp://egress"

// leasesResourceURI is the resource the model reads to find live wisp leases
// and their current URLs.
const leasesResourceURI = "gost-mcp://leases"

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

// leaseResource is one live publication as the model sees it. It deliberately
// carries no egress node addresses or credentials: the only address is the
// local target the caller itself asked to publish.
type leaseResource struct {
	Handle    string `json:"handle"`
	URL       string `json:"url"`
	Local     string `json:"local"`
	Label     string `json:"label"`
	State     string `json:"state"`
	ExpiresAt string `json:"expires_at"`
}

// addLeasesResource registers gost-mcp://leases.
func addLeasesResource(srv *mcp.Server, s *server) {
	srv.AddResource(&mcp.Resource{
		URI:  leasesResourceURI,
		Name: "leases",
		Description: "Live wisp leases and their current public URLs, with handle, local target, label, state, and expiry (RFC3339). " +
			"Read this after a relay re-bind because gost_wisp's returned URL may be stale. " +
			"Each URL is public and unauthenticated. Node addresses and credentials never appear here.",
		MIMEType: "application/json",
	}, s.readLeasesResource)
}

// readLeasesResource renders every lease, including expired records the
// provisioner still reports. An empty server returns [] rather than null so a
// model can iterate without a special case.
func (s *server) readLeasesResource(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	out := make([]leaseResource, 0)
	if s.deps.Wisp != nil {
		for _, l := range s.deps.Wisp.List() {
			out = append(out, leaseResource{
				Handle:    l.Handle,
				URL:       l.URL,
				Local:     l.Local,
				Label:     l.Label,
				State:     l.State,
				ExpiresAt: l.ExpiresAt.UTC().Format(time.RFC3339),
			})
		}
	}

	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", leasesResourceURI, err)
	}

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      leasesResourceURI,
			MIMEType: "application/json",
			Text:     string(data),
		}},
	}, nil
}
