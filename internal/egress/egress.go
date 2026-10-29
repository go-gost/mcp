// Package egress builds the dialable egress behind a named profile.
//
// Building happens once at startup: the profile is parsed into gost hop
// configs, the chain is constructed, and every later Route call only selects
// nodes. A profile is either a direct egress (zero hops) or a proxy chain; a
// chain that cannot produce a route is an error, never a silent direct dial.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/mcp/internal/config"
	_ "github.com/go-gost/mcp/internal/protocols"
	xchain "github.com/go-gost/x/chain"
	xconfig "github.com/go-gost/x/config"
	chain_parser "github.com/go-gost/x/config/parsing/chain"
	xlogger "github.com/go-gost/x/logger"
)

// ErrNoRoute reports a profile whose chain selected no nodes. It is never
// recoverable by dialing directly: that would bypass the egress.
var ErrNoRoute = errors.New("egress: no route")

// Egress is one built profile.
type Egress struct {
	Name        string
	Description string

	chain    chain.Chainer
	hops     []*xconfig.HopConfig
	hopCount int
	closed   atomic.Bool
	// lastHopNodes holds the names of the last configured hop's nodes. gost's
	// parser preserves node names (Node.Copy copies them), so a returned route
	// reaching the last hop contains at least one of these names.
	lastHopNodes map[string]struct{}
}

// Build parses the profile's chain and constructs its chainer.
//
// A zero-hop profile keeps chain nil: it is the explicit direct egress, and
// Route returns gost's DefaultRoute for it.
func Build(p *config.EgressProfile) (*Egress, error) {
	if p == nil {
		return nil, errors.New("egress: nil profile")
	}
	// Install a logger even for direct profiles: Route returns DefaultRoute,
	// whose Dial reads the global logger.
	log := defaultLogger()

	cfg, err := p.ChainConfig()
	if err != nil {
		return nil, err
	}
	if err := validateConnections(p, cfg); err != nil {
		return nil, err
	}

	e := &Egress{
		Name:        p.Name,
		Description: p.Description,
		hops:        cfg.Hops,
		hopCount:    len(cfg.Hops),
	}
	if e.hopCount == 0 {
		return e, nil
	}
	// An empty set is not "no constraint": Route treats it as unreachable, so
	// a chain whose last hop has no usable node can never produce a route.
	e.lastHopNodes = nodeNames(cfg.Hops[e.hopCount-1])

	c, err := chain_parser.ParseChain(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("egress %q: %w", p.Name, err)
	}
	if c == nil {
		return nil, fmt.Errorf("egress %q: chain produced no chainer", p.Name)
	}
	e.chain = c

	return e, nil
}

// Route selects a route for the target. It returns DefaultRoute for a direct
// egress and ErrNoRoute when the chain selects no nodes.
func (e *Egress) Route(ctx context.Context, network, address string) (chain.Route, error) {
	if e == nil {
		return nil, ErrNoRoute
	}
	if e.hopCount == 0 {
		return xchain.DefaultRoute, nil
	}
	if e.chain == nil {
		return nil, ErrNoRoute
	}

	route := e.chain.Route(ctx, network, address)
	if route == nil || len(route.Nodes()) == 0 {
		return nil, ErrNoRoute
	}
	// chain.Route stops at the first hop that selects no node and returns the
	// partial route, so a non-empty route can still be truncated. The last
	// configured hop is reached only when every hop selected a node, so require
	// one of its nodes. len(nodes) == hopCount would not work: mux dialers split
	// the route and chain.Route keeps only the final segment, which always
	// contains the last hop's node.
	if !e.reachesLastHop(route) {
		return nil, ErrNoRoute
	}
	return route, nil
}

// reachesLastHop reports whether the route includes the last configured hop.
func (e *Egress) reachesLastHop(route chain.Route) bool {
	if len(e.lastHopNodes) == 0 {
		return false
	}
	for _, node := range route.Nodes() {
		if node == nil {
			continue
		}
		if _, ok := e.lastHopNodes[node.Name]; ok {
			return true
		}
	}
	return false
}

// nodeNames returns the node names of one hop, ignoring unnamed nodes. An
// empty result means the hop cannot be proven reachable.
func nodeNames(hop *xconfig.HopConfig) map[string]struct{} {
	if hop == nil {
		return nil
	}
	names := make(map[string]struct{}, len(hop.Nodes))
	for _, node := range hop.Nodes {
		if node == nil || node.Name == "" {
			continue
		}
		names[node.Name] = struct{}{}
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// HopCount reports how many proxy hops the egress traverses. Zero means the
// explicit direct profile.
func (e *Egress) HopCount() int {
	if e == nil {
		return 0
	}
	return e.hopCount
}

// HopConfigs returns the parsed hop configs, in traversal order, so callers
// can build per-prefix profiles.
func (e *Egress) HopConfigs() []*xconfig.HopConfig {
	if e == nil {
		return nil
	}
	return e.hops
}

// Close releases the chain's probe goroutines and node resources. It is
// idempotent; a direct profile has nothing to close.
func (e *Egress) Close() error {
	if e == nil {
		return nil
	}
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	if e.chain == nil {
		return nil
	}
	if c, ok := e.chain.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Closed reports whether Close has been called. It lets callers (and tests)
// verify that a temporary egress was released.
func (e *Egress) Closed() bool {
	return e == nil || e.closed.Load()
}

// defaultLogger returns gost's global logger, installing a discard logger when
// the binary has not configured one. gost's parsing and routing code dereference
// the global logger, so a nil default panics.
func defaultLogger() logger.Logger {
	if log := logger.Default(); log != nil {
		return log
	}
	log := xlogger.Nop()
	logger.SetDefault(log)
	return log
}
