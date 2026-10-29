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

	e := &Egress{
		Name:        p.Name,
		Description: p.Description,
		hops:        cfg.Hops,
		hopCount:    len(cfg.Hops),
	}
	if e.hopCount == 0 {
		return e, nil
	}

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
	return route, nil
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
