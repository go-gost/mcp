// Command gost-mcp is a stdio MCP server exposing gost as three network
// primitives: gost-run, gost-trace, and gost-wisp/gost-unwisp.
//
// stdout is the MCP channel. Everything else, including warnings, goes to
// stderr.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/egress"
	"github.com/go-gost/mcp/internal/mcpserver"
	"github.com/go-gost/mcp/internal/wisp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gost-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		configPath     = fs.String("config", "", "path to gost-mcp.yml (default: ./gost-mcp.yml, ~/.gost-mcp/gost-mcp.yml, /etc/gost-mcp/gost-mcp.yml)")
		check          = fs.Bool("check", false, "validate the configuration, print the egress profiles, and exit")
		skipInvalid    = fs.Bool("skip-invalid", false, "skip egress profiles that fail validation instead of failing startup")
		exposeTopology = fs.Bool("expose-topology", false, "expose node addresses in the gost-mcp://egress resource")
		showVersion    = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "gost-mcp %s\n", version)
		return 0
	}

	warnf := func(format string, args ...any) {
		fmt.Fprintf(stderr, "gost-mcp: warning: "+format+"\n", args...)
	}

	warnIfGroupReadable(*configPath, warnf)

	cfg, err := config.LoadWith(*configPath, config.LoadOptions{
		SkipInvalid: *skipInvalid,
		Warnf:       warnf,
	})
	if err != nil {
		fmt.Fprintf(stderr, "gost-mcp: %v\n", err)
		return 1
	}

	if !*check {
		logger, closer, err := newLogger(cfg.Log, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "gost-mcp: %v\n", err)
			return 1
		}
		if closer != nil {
			defer closer.Close()
		}
		slog.SetDefault(logger)

		var reg *egress.Registry
		if *skipInvalid {
			reg, err = egress.BuildAllSkipping(cfg.Egress, warnf)
		} else {
			reg, err = egress.BuildAll(cfg.Egress)
		}
		if err != nil {
			fmt.Fprintf(stderr, "gost-mcp: %v\n", err)
			return 1
		}
		defer reg.Close()

		fmt.Fprintf(stderr, "gost-mcp %s: %d egress profile(s) resolved; waiting for MCP messages on stdio\n",
			version, len(reg.Profiles()))

		wp := wisp.New(cfg.Wisp, nil)
		defer wp.Close()

		srv := mcpserver.New(cfg, mcpserver.Deps{
			Egress:         reg,
			ExposeTopology: *exposeTopology,
			Wisp:           wp,
			Logger:         logger,
			Version:        version,
		})

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(stderr, "gost-mcp: %v\n", err)
			return 1
		}
		fmt.Fprintln(stderr, "gost-mcp: server stopped")
		return 0
	}

	if err := printProfiles(stdout, cfg, *skipInvalid, warnf); err != nil {
		fmt.Fprintf(stderr, "gost-mcp: %v\n", err)
		return 1
	}
	return 0
}

// newLogger builds the process logger from log.level and log.file. MCP owns
// stdout, so an empty log.file writes to stderr.
func newLogger(cfg config.LogConfig, stderr io.Writer) (*slog.Logger, io.Closer, error) {
	w := stderr
	var closer io.Closer
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("log.file: %w", err)
		}
		w, closer = f, f
	}

	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(cfg.Level)) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})), closer, nil
}

// warnIfGroupReadable warns when the config file may leak credentials to
// other local users.
func warnIfGroupReadable(path string, warnf func(string, ...any)) {
	resolved, err := config.ResolvePath(path)
	if err != nil {
		return // LoadWith reports it.
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		warnf("%s is accessible by group or others (%04o); it may contain credentials, use 0600", resolved, perm)
	}
}

// printProfiles builds every profile and prints one line: name, description,
// hop count, and node count. Building here is what catches a bad node address
// or an unregistered chain scheme; addresses and credentials are never printed.
func printProfiles(w io.Writer, cfg *config.Config, skipInvalid bool, warnf func(string, ...any)) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	printed := 0
	for i := range cfg.Egress {
		p := &cfg.Egress[i]
		e, err := egress.Build(p)
		if err != nil {
			if skipInvalid {
				warnf("skipping egress profile: %v", err)
				continue
			}
			return err
		}
		e.Close()
		chain, err := p.ChainConfig()
		if err != nil {
			if skipInvalid {
				warnf("skipping egress profile: %v", err)
				continue
			}
			return err
		}
		var nodes int
		for _, hop := range chain.Hops {
			if hop != nil {
				nodes += len(hop.Nodes)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			p.Name, singleLine(p.Description), plural(len(chain.Hops), "hop"), plural(nodes, "node"))
		printed++
	}
	if printed == 0 {
		return errors.New("no usable egress profiles")
	}
	return tw.Flush()
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func singleLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
