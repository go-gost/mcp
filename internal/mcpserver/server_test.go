package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/egress"
	"github.com/go-gost/mcp/internal/testutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testConfig returns the profile set used by most tests: an explicit direct
// egress and a proxy egress whose address cannot be reached. Tests that need to
// make a request build their own profile pointing at a local proxy. The proxy
// chain URI carries userinfo so the default profiles exercise the credential
// path too; gost moves it into the connector auth and never into node.Addr.
func testConfig() *config.Config {
	return &config.Config{
		Egress: []config.EgressProfile{
			{Name: "direct", Description: "Host direct, no proxy", Chain: []string{}},
			{Name: "jp", Description: "Tokyo residential exit", Chain: []string{"socks5://alice:hunter2@tokyo.example.com:1080"}},
		},
		Run: config.RunConfig{
			Timeout:  5 * time.Second,
			MaxBytes: 1 << 20,
		},
		Trace: config.TraceConfig{
			Timeout:     5 * time.Second,
			IdentityURL: "https://ifconfig.co/json",
		},
	}
}

// newTestSession starts the server on an in-memory transport and returns a
// connected client session.
func newTestSession(t *testing.T, cfg *config.Config, exposeTopology bool) *mcp.ClientSession {
	t.Helper()

	reg, err := egress.BuildAll(cfg.Egress)
	if err != nil {
		t.Fatalf("BuildAll: %v", err)
	}

	server := New(cfg, Deps{Egress: reg, ExposeTopology: exposeTopology, Version: "test"})

	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	return cs
}

// resultText joins the text blocks of a tool result.
func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// structured returns the structured content as the client decodes it.
func structured(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	m, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("StructuredContent = %T (%v), want map[string]any", res.StructuredContent, res.StructuredContent)
	}
	return m
}

func TestToolCatalog(t *testing.T) {
	cs := newTestSession(t, testConfig(), false)
	ctx := context.Background()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	tools := make(map[string]*mcp.Tool, len(res.Tools))
	for _, tool := range res.Tools {
		tools[tool.Name] = tool
	}

	for _, name := range []string{"gost_run", "gost_trace"} {
		tool, ok := tools[name]
		if !ok {
			t.Fatalf("tool %q not listed; got %v", name, toolNames(res.Tools))
		}
		if !strings.Contains(strings.ToLower(tool.Description), "egress") {
			t.Errorf("%s description does not mention egress: %q", name, tool.Description)
		}
	}

	trace := tools["gost_trace"]
	if !strings.Contains(trace.Description, "cumulative chain prefixes") {
		t.Errorf("gost_trace description does not mention cumulative chain prefixes: %q", trace.Description)
	}
	if !strings.Contains(trace.Description, "not per-hop TTL hops") {
		t.Errorf("gost_trace description does not contrast per-hop TTL hops: %q", trace.Description)
	}
}

func toolNames(tools []*mcp.Tool) []string {
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = tool.Name
	}
	return names
}

func TestRunRequiresEgress(t *testing.T) {
	cs := newTestSession(t, testConfig(), false)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "gost_run",
		Arguments: map[string]any{"url": "http://example.com/"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("IsError = false, want true; result = %v", res)
	}
	if msg := resultText(res); !strings.Contains(strings.ToLower(msg), "egress") {
		t.Errorf("error %q does not mention egress", msg)
	}
}

func TestRunUnknownEgressListsNames(t *testing.T) {
	cs := newTestSession(t, testConfig(), false)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "gost_run",
		Arguments: map[string]any{"egress": "nope", "url": "http://example.com/"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("IsError = false, want true; result = %v", res)
	}
	if msg := resultText(res); !strings.Contains(msg, "jp") || !strings.Contains(msg, "direct") {
		t.Errorf("error %q does not list the configured profile names", msg)
	}
}

func TestRunProxiesRequest(t *testing.T) {
	proxy := testutil.NewHTTPProxy(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("hello through the proxy"))
	}))
	t.Cleanup(target.Close)

	cfg := testConfig()
	cfg.Egress = []config.EgressProfile{
		{Name: "jp", Description: "Local proxy", Chain: []string{"http://" + proxy}},
	}
	cs := newTestSession(t, cfg, false)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "gost_run",
		Arguments: map[string]any{
			"egress": "jp",
			"url":    target.URL,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError = true: %s", resultText(res))
	}

	out := structured(t, res)
	if out["ok"] != true {
		t.Fatalf("ok = %v, want true; failure = %v", out["ok"], out["failure"])
	}
	if out["status"] != float64(http.StatusOK) {
		t.Errorf("status = %v, want 200", out["status"])
	}
	if out["body"] != "hello through the proxy" {
		t.Errorf("body = %v", out["body"])
	}
	eg, ok := out["egress"].(map[string]any)
	if !ok || eg["name"] != "jp" {
		t.Errorf("egress = %v, want name jp", out["egress"])
	}
}

func TestRunRejectsInvalidBase64Body(t *testing.T) {
	cs := newTestSession(t, testConfig(), false)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "gost_run",
		Arguments: map[string]any{
			"egress":        "direct",
			"url":           "http://example.com/",
			"body":          "not base64!",
			"body_encoding": "base64",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("IsError = false, want true; result = %v", res)
	}
	if msg := resultText(res); !strings.Contains(strings.ToLower(msg), "base64") {
		t.Errorf("error %q does not mention base64", msg)
	}
}

func TestTraceReturnsStructuredReport(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	cs := newTestSession(t, testConfig(), false)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "gost_trace",
		Arguments: map[string]any{
			"egress": "direct",
			"target": target.URL,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError = true: %s", resultText(res))
	}

	out := structured(t, res)
	if out["ok"] != true {
		t.Fatalf("ok = %v, want true; failure = %v", out["ok"], out["failure"])
	}
	if out["target"] != target.URL {
		t.Errorf("target = %v, want %v", out["target"], target.URL)
	}
	if _, ok := out["mode"].(string); !ok {
		t.Errorf("mode missing or not a string: %v", out["mode"])
	}
	stages, ok := out["stages"].([]any)
	if !ok || len(stages) == 0 {
		t.Errorf("stages = %v, want a non-empty list", out["stages"])
	}
	// prefix defaults to true, so the direct profile still reports one probe.
	prefixes, ok := out["prefixes"].([]any)
	if !ok || len(prefixes) == 0 {
		t.Errorf("prefixes = %v, want a non-empty list (prefix defaults to true)", out["prefixes"])
	}
	eg, ok := out["egress"].(map[string]any)
	if !ok || eg["name"] != "direct" {
		t.Errorf("egress = %v, want name direct", out["egress"])
	}
}

func TestEgressResourceHidesTopology(t *testing.T) {
	cs := newTestSession(t, testConfig(), false)

	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gost-mcp://egress"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("contents = %d, want 1", len(res.Contents))
	}
	text := res.Contents[0].Text

	var profiles []map[string]any
	if err := json.Unmarshal([]byte(text), &profiles); err != nil {
		t.Fatalf("resource is not JSON: %v\n%s", err, text)
	}
	if len(profiles) != 2 {
		t.Fatalf("profiles = %d, want 2: %s", len(profiles), text)
	}
	for _, p := range profiles {
		if len(p) != 2 {
			t.Errorf("profile keys = %v, want only name and description", p)
		}
		if _, ok := p["name"].(string); !ok {
			t.Errorf("profile has no name: %v", p)
		}
		if _, ok := p["description"].(string); !ok {
			t.Errorf("profile has no description: %v", p)
		}
	}
	if strings.Contains(text, "socks5://") {
		t.Errorf("resource leaks a chain URI:\n%s", text)
	}
	if strings.Contains(text, "tokyo.example.com") {
		t.Errorf("resource leaks a node address:\n%s", text)
	}
}

func TestEgressResourceExposesTopology(t *testing.T) {
	cs := newTestSession(t, testConfig(), true)

	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gost-mcp://egress"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	text := res.Contents[0].Text

	var profiles []map[string]any
	if err := json.Unmarshal([]byte(text), &profiles); err != nil {
		t.Fatalf("resource is not JSON: %v\n%s", err, text)
	}

	var jp map[string]any
	for _, p := range profiles {
		if p["name"] == "jp" {
			jp = p
		}
	}
	if jp == nil {
		t.Fatalf("profile jp missing: %s", text)
	}
	nodes, ok := jp["nodes"].([]any)
	if !ok || len(nodes) == 0 {
		t.Fatalf("exposed profile has no nodes: %v", jp)
	}
	if !strings.Contains(text, "tokyo.example.com") {
		t.Errorf("exposed topology does not include the node address:\n%s", text)
	}
	if strings.Contains(text, "socks5://") {
		t.Errorf("exposed topology still leaks a chain URI:\n%s", text)
	}
	for _, credential := range []string{"alice", "hunter2"} {
		if strings.Contains(text, credential) {
			t.Errorf("exposed topology leaks chain userinfo %q:\n%s", credential, text)
		}
	}
}

// credentialConfig loads the fixture whose profiles embed userinfo in a chain
// URI and in hand-written hop node addresses.
func credentialConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("testdata/credentials.yml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// TestEgressResourceStripsCredentials is the regression test for the topology
// path: the resource may name the host, but never the userinfo of a chain URI
// or of a hand-written hop node address.
func TestEgressResourceStripsCredentials(t *testing.T) {
	for _, expose := range []bool{false, true} {
		name := "without topology"
		if expose {
			name = "with topology"
		}
		t.Run(name, func(t *testing.T) {
			cs := newTestSession(t, credentialConfig(t), expose)

			res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gost-mcp://egress"})
			if err != nil {
				t.Fatalf("ReadResource: %v", err)
			}
			if len(res.Contents) != 1 {
				t.Fatalf("contents = %d, want 1", len(res.Contents))
			}
			text := res.Contents[0].Text

			for _, credential := range []string{"alice", "hunter2", "bob", "carol", "s3cret"} {
				if strings.Contains(text, credential) {
					t.Errorf("resource leaks credential %q:\n%s", credential, text)
				}
			}

			// Without --expose-topology the payload is name + description only,
			// so no address is emitted at all; with it, the host survives.
			for _, host := range []string{"tokyo.example.com", "osaka.example.com", "nagoya.example.com"} {
				if got := strings.Contains(text, host); got != expose {
					t.Errorf("contains(%q) = %v, want %v (--expose-topology = %v):\n%s",
						host, got, expose, expose, text)
				}
			}
		})
	}
}

func TestStripUserInfo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"scheme with credentials", "socks5://user:pass@host:1080", "socks5://host:1080"},
		{"scheme-less with credentials", "user:pass@host:8080", "host:8080"},
		{"scheme-less without password", "user@host:8080", "host:8080"},
		{"scheme-less without port", "user:pass@host", "host"},
		{"escaped separator", "socks5://user:p%40ss@host:1080", "socks5://host:1080"},
		{"ipv6 host", "socks5://user:pass@[::1]:1080", "socks5://[::1]:1080"},
		{"no credentials", "host:8080", "host:8080"},
		{"scheme without credentials", "socks5://host:1080", "socks5://host:1080"},
		{"empty", "", ""},
		{"at in path is not credentials", "http://host:8080/a@b", "http://host:8080/a@b"},
		{"at in query is not credentials", "socks5://host:1080?auth=a@b", "socks5://host:1080?auth=a@b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripUserInfo(tt.in); got != tt.want {
				t.Errorf("stripUserInfo(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestToolLimits(t *testing.T) {
	s := &server{cfg: &config.Config{}}

	if got := s.runTimeout(0); got != config.DefaultRunTimeout {
		t.Errorf("runTimeout(0) = %v, want %v", got, config.DefaultRunTimeout)
	}
	if got := s.runTimeout(1_000_000); got != maxRunTimeout {
		t.Errorf("runTimeout(1000000) = %v, want %v", got, maxRunTimeout)
	}
	if got := s.runMaxBytes(0); got != config.DefaultRunMaxBytes {
		t.Errorf("runMaxBytes(0) = %v, want %v", got, config.DefaultRunMaxBytes)
	}
	if got := s.runMaxBytes(1 << 30); got != maxRunMaxBytes {
		t.Errorf("runMaxBytes(1GiB) = %v, want %v", got, maxRunMaxBytes)
	}
	if got := s.traceTimeout(0); got != config.DefaultTraceTimeout {
		t.Errorf("traceTimeout(0) = %v, want %v", got, config.DefaultTraceTimeout)
	}
	if got := s.traceTimeout(1_000_000); got != maxTraceTimeout {
		t.Errorf("traceTimeout(1000000) = %v, want %v", got, maxTraceTimeout)
	}
}

func TestTraceConcurrencyCap(t *testing.T) {
	s := &server{cfg: &config.Config{}, traceSem: make(chan struct{}, 2)}

	release1, err := s.acquireTrace()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	release2, err := s.acquireTrace()
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}

	if _, err := s.acquireTrace(); err == nil {
		t.Fatal("third acquire succeeded, want a clear busy error")
	} else if !strings.Contains(err.Error(), "already running") {
		t.Errorf("busy error = %q", err)
	}

	release1()
	if _, err := s.acquireTrace(); err != nil {
		t.Errorf("acquire after release: %v", err)
	}
	release2()
}
