// Command gost-mcp is a stdio MCP server exposing gost as three network
// primitives: gost_run, gost_trace, and gost_wisp/gost_unwisp.
//
// stdout is the MCP channel. Everything else, including warnings, goes to
// stderr.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/go-gost/mcp/internal/config"
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
	_ = *exposeTopology // consumed by the MCP server in a later step

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
		fmt.Fprintln(stderr, "gost-mcp: the MCP server is not implemented yet; use --check to validate the configuration")
		return 1
	}

	if err := printProfiles(stdout, cfg); err != nil {
		fmt.Fprintf(stderr, "gost-mcp: %v\n", err)
		return 1
	}
	return 0
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

// printProfiles prints one line per profile: name, description, hop count,
// and node count. Addresses and credentials are deliberately omitted.
func printProfiles(w io.Writer, cfg *config.Config) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for i := range cfg.Egress {
		p := &cfg.Egress[i]
		chain, err := p.ChainConfig()
		if err != nil {
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
