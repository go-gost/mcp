package wisp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/service"
	"github.com/go-gost/mcp/internal/config"

	// Register the connectors, dialers, handlers, and listeners the rtcp
	// service and tunnel+wss relay reference.
	_ "github.com/go-gost/mcp/internal/protocols"

	"github.com/go-gost/x/config/cmd"
	chain_parser "github.com/go-gost/x/config/parsing/chain"
	service_parser "github.com/go-gost/x/config/parsing/service"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/registry"
)

// chainNames maps a built service to the registry name of its chain so Release
// can unregister exactly the chain it created. Entries exist only for services
// built by realServiceFactory.
var chainNames sync.Map

// realServiceFactory wires the same service as
//
//	gost -L rtcp://:0/<local> -F tunnel+wss://<relay>
//
// but keeps the chain per lease: every call registers a uniquely named chain
// and points the service at it.
func realServiceFactory(cfg config.WispConfig) ServiceFactory {
	return func(ctx context.Context, local string) (service.Service, error) {
		return newRealService(ctx, cfg, local)
	}
}

func newRealService(ctx context.Context, cfg config.WispConfig, local string) (service.Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	relay := cfg.Relay
	if relay == "" {
		relay = config.DefaultWispRelay
	}

	log := ensureLogger()

	bcfg, err := cmd.BuildConfigFromCmd([]string{"rtcp://:0/" + local}, []string{relay})
	if err != nil {
		return nil, fmt.Errorf("wisp: build config: %w", err)
	}
	if len(bcfg.Chains) == 0 {
		return nil, errors.New("wisp: relay produced no chain")
	}
	if len(bcfg.Services) == 0 {
		return nil, errors.New("wisp: service list produced no service")
	}

	ch, err := chain_parser.ParseChain(bcfg.Chains[0], log)
	if err != nil {
		return nil, fmt.Errorf("wisp: parse chain: %w", err)
	}
	if ch == nil {
		return nil, errors.New("wisp: relay produced no chainer")
	}

	name, err := chainName(ctx)
	if err != nil {
		return nil, err
	}
	if err := registry.ChainRegistry().Register(name, ch); err != nil {
		return nil, fmt.Errorf("wisp: register chain: %w", err)
	}

	svcCfg := bcfg.Services[0]
	if svcCfg.Listener == nil {
		registry.ChainRegistry().Unregister(name)
		return nil, errors.New("wisp: service has no listener")
	}
	// BuildConfigFromCmd attaches the chain to the listener for remote
	// protocols and to the handler otherwise; keep that placement.
	switch svcCfg.Listener.Type {
	case "rtcp", "rudp", "runix":
		svcCfg.Listener.Chain = name
	default:
		if svcCfg.Handler == nil {
			registry.ChainRegistry().Unregister(name)
			return nil, errors.New("wisp: service has no handler")
		}
		svcCfg.Handler.Chain = name
	}

	svc, err := service_parser.ParseService(svcCfg)
	if err != nil {
		registry.ChainRegistry().Unregister(name)
		return nil, fmt.Errorf("wisp: parse service: %w", err)
	}
	if svc == nil {
		registry.ChainRegistry().Unregister(name)
		return nil, errors.New("wisp: service parser returned nil")
	}

	chainNames.Store(svc, name)
	return svc, nil
}

// chainName returns lease-<handle>, using the handle Provision carries in the
// context. A direct realServiceFactory call (tests) gets a fresh unique name.
func chainName(ctx context.Context) (string, error) {
	if handle, ok := ctx.Value(handleKey{}).(string); ok && handle != "" {
		return "lease-" + handle, nil
	}
	handle, err := newHandle()
	if err != nil {
		return "", err
	}
	return "lease-" + handle, nil
}

// releaseReal unregisters the chain created for svc. It is a no-op for
// services built by an injected factory.
func releaseReal(svc service.Service) {
	if svc == nil {
		return
	}
	value, ok := chainNames.LoadAndDelete(svc)
	if !ok {
		return
	}
	if name, ok := value.(string); ok {
		registry.ChainRegistry().Unregister(name)
	}
}

// ensureLogger installs a no-op logger when the binary has not configured one;
// gost's parsers dereference the global logger.
func ensureLogger() logger.Logger {
	if log := logger.Default(); log != nil {
		return log
	}
	log := xlogger.Nop()
	logger.SetDefault(log)
	return log
}
