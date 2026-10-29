// Package mcpserver exposes gost as MCP tools over a stdio transport.
//
// The server owns no network listener beyond the tool calls themselves: every
// tool resolves a named egress profile and performs exactly the operation the
// caller asked for through it. There is no implicit direct connection.
package mcpserver

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/egress"
	"github.com/go-gost/mcp/internal/wisp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool limits. They bound a single call regardless of what the configuration
// allows, so a model cannot ask the process to hold a connection open or buffer
// a response indefinitely.
const (
	maxRunTimeout   = 120 * time.Second
	maxRunMaxBytes  = 8 << 20 // 8 MiB
	maxTraceTimeout = 60 * time.Second

	// maxConcurrentTraces bounds abandoned dial goroutines and file
	// descriptors: trace.Run cannot cancel a CONNECT handshake that a
	// blackholed proxy is holding, so unchecked concurrent traces could
	// accumulate goroutines until the peer times out.
	maxConcurrentTraces = 8
)

// Deps are the runtime dependencies of the MCP server.
type Deps struct {
	// Egress holds the configured profiles. A nil registry is allowed and
	// makes every tool call fail with an argument error naming no profiles.
	Egress *egress.Registry

	// ExposeTopology adds node addresses to the gost-mcp://egress resource.
	// Off by default: the model sees only names and descriptions.
	ExposeTopology bool

	// Wisp publishes local services for gost_wisp. A nil provisioner is
	// allowed: the wisp tools report that publishing is not configured and
	// the gost-mcp://leases resource is empty.
	Wisp wisp.Provisioner

	// Version is reported as the MCP implementation version.
	Version string
}

// server holds the state shared by the tool handlers.
type server struct {
	cfg  *config.Config
	deps Deps

	// traceSem limits simultaneous gost_trace calls.
	traceSem chan struct{}
}

// New builds the MCP server with gost_run, gost_trace, gost_wisp,
// gost_unwisp, and the gost-mcp://egress and gost-mcp://leases resources
// registered.
func New(cfg *config.Config, deps Deps) *mcp.Server {
	if cfg == nil {
		cfg = &config.Config{}
	}
	s := &server{
		cfg:      cfg,
		deps:     deps,
		traceSem: make(chan struct{}, maxConcurrentTraces),
	}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "gost-mcp",
		Version: deps.Version,
	}, nil)

	mcp.AddTool(srv, runTool(), s.handleRun)
	mcp.AddTool(srv, traceTool(), s.handleTrace)
	mcp.AddTool(srv, wispTool(), s.handleWisp)
	mcp.AddTool(srv, unwispTool(), s.handleUnwisp)
	addEgressResource(srv, s)
	addLeasesResource(srv, s)

	return srv
}

// egressRef is the egress name echoed in tool output.
type egressRef struct {
	Name string `json:"name"`
}

// resolveEgress maps a profile name to a built egress. An unknown name is an
// argument error that lists the configured names, never a fallback to direct.
func (s *server) resolveEgress(name string) (*egress.Egress, egressRef, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, egressRef{}, fmt.Errorf("egress is required; available profiles: %s", s.profileNames())
	}
	e, ok := s.deps.Egress.Get(name)
	if !ok {
		return nil, egressRef{}, fmt.Errorf("unknown egress %q; available profiles: %s", name, s.profileNames())
	}
	return e, egressRef{Name: e.Name}, nil
}

// profileNames lists the configured profile names, in declaration order.
func (s *server) profileNames() string {
	profiles := s.deps.Egress.Profiles()
	if len(profiles) == 0 {
		return "(none configured)"
	}
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.Name
	}
	return strings.Join(names, ", ")
}

// acquireTrace takes one of the trace slots. It never blocks: a full server
// reports back instead of queueing an unbounded number of abandoned dials.
func (s *server) acquireTrace() (release func(), err error) {
	select {
	case s.traceSem <- struct{}{}:
		return func() { <-s.traceSem }, nil
	default:
		return nil, fmt.Errorf("gost_trace: %d traces are already running; retry when one completes", cap(s.traceSem))
	}
}

// boolPtr returns a pointer to v for optional annotations and defaults.
func boolPtr(v bool) *bool { return &v }
