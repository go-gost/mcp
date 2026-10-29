package egress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/testutil"
	xconfig "github.com/go-gost/x/config"
	chain_parser "github.com/go-gost/x/config/parsing/chain"
	"github.com/go-gost/x/registry"
)

// startTarget runs an HTTP origin server and returns its host:port address.
func startTarget(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	return strings.TrimPrefix(srv.URL, "http://")
}

// readOK sends one GET over conn and returns the response body.
func readOK(t *testing.T, conn net.Conn, addr string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Close = true
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

func directProfile() *config.EgressProfile {
	return &config.EgressProfile{
		Name:        "direct",
		Description: "no proxy",
		Chain:       []string{},
	}
}

func TestBuildDirectProfile(t *testing.T) {
	e, err := Build(directProfile())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := e.HopCount(); got != 0 {
		t.Fatalf("HopCount = %d, want 0", got)
	}
	if got := e.HopConfigs(); len(got) != 0 {
		t.Fatalf("HopConfigs = %d hops, want 0", len(got))
	}

	addr := startTarget(t)
	route, err := e.Route(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if route == nil {
		t.Fatal("Route = nil, want the direct route")
	}

	conn, err := route.Dial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if got := readOK(t, conn, addr); got != "ok" {
		t.Fatalf("body = %q, want %q", got, "ok")
	}
}

func TestRouteThroughHTTPProxy(t *testing.T) {
	proxyAddr := testutil.NewHTTPProxy(t)

	e, err := Build(&config.EgressProfile{
		Name:        "via-proxy",
		Description: "one HTTP proxy hop",
		Chain:       []string{"http://" + proxyAddr},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := e.HopCount(); got != 1 {
		t.Fatalf("HopCount = %d, want 1", got)
	}

	addr := startTarget(t)
	route, err := e.Route(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	conn, err := route.Dial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	if got := readOK(t, conn, addr); got != "ok" {
		t.Fatalf("body = %q, want %q", got, "ok")
	}
}

// TestRouteRejectsEmptyRoute pins the no-route rule: a hop with no nodes must
// fail instead of silently falling back to a direct dial.
func TestRouteRejectsEmptyRoute(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
		accepted <- struct{}{}
	}()

	e, err := Build(&config.EgressProfile{
		Name:        "broken",
		Description: "hop without nodes",
		Hops: []*xconfig.HopConfig{
			{Name: "hop-0", Nodes: []*xconfig.NodeConfig{}},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := e.HopCount(); got != 1 {
		t.Fatalf("HopCount = %d, want 1", got)
	}

	route, err := e.Route(context.Background(), "tcp", ln.Addr().String())
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("Route error = %v, want ErrNoRoute", err)
	}
	if route != nil {
		t.Fatalf("Route = %v, want nil", route)
	}

	select {
	case <-accepted:
		t.Fatal("Route dialed the target, want no connection attempt")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestBuildRegistersSocks5Connector proves internal/protocols is imported:
// without the blank imports gost reports "unregistered connector: socks5".
func TestBuildRegistersSocks5Connector(t *testing.T) {
	e, err := Build(&config.EgressProfile{
		Name:        "socks",
		Description: "socks5 node",
		Chain:       []string{"socks5://127.0.0.1:1080"},
	})
	if err != nil {
		t.Fatalf("Build: %v (is internal/protocols imported?)", err)
	}

	hops := e.HopConfigs()
	if len(hops) != 1 || len(hops[0].Nodes) != 1 {
		t.Fatalf("HopConfigs = %+v, want one hop with one node", hops)
	}
	if got := hops[0].Nodes[0].Connector.Type; got != "socks5" {
		t.Fatalf("connector type = %q, want %q", got, "socks5")
	}
	if registry.ConnectorRegistry().Get("socks5") == nil {
		t.Fatal("socks5 connector is not registered")
	}

	route, err := e.Route(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if got := len(route.Nodes()); got != 1 {
		t.Fatalf("route nodes = %d, want 1", got)
	}
}

// TestRouteRejectsTruncatedMultiHop pins the fail-closed rule for partial
// routes: chain.Route stops at the first hop that selects no node and returns
// what it has, so a non-empty route can still skip the last configured hop.
func TestRouteRejectsTruncatedMultiHop(t *testing.T) {
	p1 := &xconfig.NodeConfig{Name: "p1", Addr: "http://127.0.0.1:8080"}

	tests := []struct {
		name      string
		lastHop   *xconfig.HopConfig
		lastNames map[string]struct{}
		wantErr   bool
	}{
		{
			name:      "empty last hop",
			lastHop:   &xconfig.HopConfig{Name: "hop-1", Nodes: []*xconfig.NodeConfig{}},
			lastNames: map[string]struct{}{},
			wantErr:   true,
		},
		{
			// ParseChain silently drops a hop reference it cannot resolve.
			name:      "unresolved hop reference",
			lastHop:   &xconfig.HopConfig{Name: "ghost"},
			lastNames: map[string]struct{}{"ghost": {}},
			wantErr:   true,
		},
		{
			name:      "complete chain",
			lastHop:   &xconfig.HopConfig{Name: "hop-1", Nodes: []*xconfig.NodeConfig{{Name: "p2", Addr: "http://127.0.0.1:8081"}}},
			lastNames: map[string]struct{}{"p2": {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &xconfig.ChainConfig{
				Name: "trunc",
				Hops: []*xconfig.HopConfig{
					{Name: "hop-0", Nodes: []*xconfig.NodeConfig{p1}},
					tt.lastHop,
				},
			}
			c, err := chain_parser.ParseChain(cfg, defaultLogger())
			if err != nil {
				t.Fatalf("ParseChain: %v", err)
			}

			e := &Egress{
				Name:         "trunc",
				hops:         cfg.Hops,
				hopCount:     2,
				chain:        c,
				lastHopNodes: tt.lastNames,
			}
			route, err := e.Route(context.Background(), "tcp", "example.com:80")
			if tt.wantErr {
				if !errors.Is(err, ErrNoRoute) {
					t.Fatalf("Route error = %v, want ErrNoRoute", err)
				}
				if route != nil {
					t.Fatalf("Route = %v, want nil", route)
				}
				return
			}
			if err != nil {
				t.Fatalf("Route: %v", err)
			}
			if got := len(route.Nodes()); got != 2 {
				t.Fatalf("route nodes = %d, want 2", got)
			}
		})
	}
}

// TestRouteDoesNotFallBackToDirect proves a denying proxy cannot be bypassed:
// the target is reachable directly, so a successful dial would mean the egress
// dialed around the proxy.
func TestRouteDoesNotFallBackToDirect(t *testing.T) {
	addr := startTarget(t)
	proxyAddr := testutil.NewHTTPProxy(t, addr)

	e, err := Build(&config.EgressProfile{
		Name:        "via-proxy",
		Description: "proxy denies the target",
		Chain:       []string{"http://" + proxyAddr},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	route, err := e.Route(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	conn, err := route.Dial(context.Background(), "tcp", addr)
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded, want the proxy to deny the target; a direct dial would have bypassed the egress")
	}
}

func TestBuildAllRejectsDuplicateNames(t *testing.T) {
	_, err := BuildAll([]config.EgressProfile{
		{Name: "jp", Description: "first", Chain: []string{}},
		{Name: "jp", Description: "second", Chain: []string{}},
	})
	if err == nil {
		t.Fatal("BuildAll succeeded, want a duplicate-name error")
	}
	if !strings.Contains(err.Error(), "jp") {
		t.Fatalf("error = %v, want it to name the duplicate profile", err)
	}
}

func TestRegistryUnknownName(t *testing.T) {
	r, err := BuildAll([]config.EgressProfile{*directProfile()})
	if err != nil {
		t.Fatalf("BuildAll: %v", err)
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("Get(nope) = true, want false")
	}
	if e, ok := r.Get("direct"); !ok || e.Name != "direct" {
		t.Fatalf("Get(direct) = %v, %v; want the direct egress", e, ok)
	}
}

func TestRegistryProfilesPreserveOrder(t *testing.T) {
	r, err := BuildAll([]config.EgressProfile{
		{Name: "direct", Description: "no proxy", Chain: []string{}},
		{Name: "jp", Description: "tokyo", Chain: []string{"http://127.0.0.1:8080"}},
	})
	if err != nil {
		t.Fatalf("BuildAll: %v", err)
	}

	got := r.Profiles()
	want := []Profile{
		{Name: "direct", Description: "no proxy"},
		{Name: "jp", Description: "tokyo"},
	}
	if len(got) != len(want) {
		t.Fatalf("Profiles() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Profiles()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
