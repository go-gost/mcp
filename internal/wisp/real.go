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
//	gost -L rtcp://:0/<addr> -F tunnel+wss://<relay>
//
// but keeps the chain per lease: every call registers a uniquely named chain
// and points the service at it. addr is already resolved and allow-listed by
// the provisioner, so the rtcp handler never re-resolves a hostname.
func realServiceFactory(cfg config.WispConfig) ServiceFactory {
	return func(ctx context.Context, name, addr string) (service.Service, error) {
		return newRealService(ctx, cfg, name, addr)
	}
}

func newRealService(ctx context.Context, cfg config.WispConfig, name, addr string) (service.Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	leaseName, err := leaseName(name)
	if err != nil {
		return nil, err
	}

	relay := cfg.Relay
	if relay == "" {
		relay = config.DefaultWispRelay
	}

	log := ensureLogger()

	bcfg, err := cmd.BuildConfigFromCmd([]string{"rtcp://:0/" + addr}, []string{relay})
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

	if err := registry.ChainRegistry().Register(leaseName, ch); err != nil {
		return nil, fmt.Errorf("wisp: register chain: %w", err)
	}

	svcCfg := bcfg.Services[0]
	if svcCfg.Listener == nil {
		registry.ChainRegistry().Unregister(leaseName)
		return nil, errors.New("wisp: service has no listener")
	}
	// BuildConfigFromCmd names every service "service-0". Overwrite it with
	// the lease name so concurrent leases never share a service identity.
	svcCfg.Name = leaseName
	// BuildConfigFromCmd attaches the chain to the listener for remote
	// protocols and to the handler otherwise; keep that placement.
	switch svcCfg.Listener.Type {
	case "rtcp", "rudp", "runix":
		svcCfg.Listener.Chain = leaseName
	default:
		if svcCfg.Handler == nil {
			registry.ChainRegistry().Unregister(leaseName)
			return nil, errors.New("wisp: service has no handler")
		}
		svcCfg.Handler.Chain = leaseName
	}

	svc, err := service_parser.ParseService(svcCfg)
	if err != nil {
		registry.ChainRegistry().Unregister(leaseName)
		return nil, fmt.Errorf("wisp: parse service: %w", err)
	}
	if svc == nil {
		registry.ChainRegistry().Unregister(leaseName)
		return nil, errors.New("wisp: service parser returned nil")
	}

	chainNames.Store(svc, leaseName)
	return svc, nil
}

// leaseName returns name, or a fresh "lease-<handle>" for a direct
// realServiceFactory call with no name (tests).
func leaseName(name string) (string, error) {
	if name != "" {
		return name, nil
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
