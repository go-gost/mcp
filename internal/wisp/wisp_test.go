package wisp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/core/service"
	"github.com/go-gost/mcp/internal/config"
)

// testAddr is a minimal net.Addr whose String form is "<host>:0". It stands in
// for the server-negotiated address an rtcp listener reports after binding.
type testAddr struct {
	host string
}

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return a.host + ":0" }

// fakeService is a service.Service whose address can change while running and
// whose Close is observable.
type fakeService struct {
	mu      sync.Mutex
	addr    net.Addr
	closes  atomic.Int32
	done    chan struct{}
	stopped sync.Once
}

func newFakeService(addr net.Addr) *fakeService {
	return &fakeService{addr: addr, done: make(chan struct{})}
}

func (s *fakeService) Serve() error {
	<-s.done
	return nil
}

func (s *fakeService) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

func (s *fakeService) setAddr(addr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addr = addr
}

func (s *fakeService) Close() error {
	s.closes.Add(1)
	s.stopped.Do(func() { close(s.done) })
	return nil
}

func staticFactory(svc service.Service) ServiceFactory {
	return func(context.Context, string) (service.Service, error) { return svc, nil }
}

func testConfig() config.WispConfig {
	return config.WispConfig{
		Domain:    "gost.run",
		MaxTTL:    time.Hour,
		MaxLeases: 4,
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func TestProvisionReturnsPublicURL(t *testing.T) {
	svc := newFakeService(testAddr{})
	// Stay unbound for a moment so Provision has to poll.
	go func() {
		time.Sleep(20 * time.Millisecond)
		svc.setAddr(testAddr{host: "abc123"})
	}()

	p := New(testConfig(), staticFactory(svc))
	lease, err := p.Provision(context.Background(), Request{
		Local: "127.0.0.1:8080",
		Label: "demo",
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got, want := lease.URL, "https://abc123.gost.run"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
	if got, want := lease.State, StateActive; got != want {
		t.Errorf("State = %q, want %q", got, want)
	}
	if lease.Handle == "" {
		t.Error("Handle is empty")
	}
	if lease.Local != "127.0.0.1:8080" || lease.Label != "demo" {
		t.Errorf("Local/Label = %q/%q, want 127.0.0.1:8080/demo", lease.Local, lease.Label)
	}
	if lease.Verify != nil {
		t.Errorf("Verify = %+v, want nil when verification was not requested", lease.Verify)
	}

	if _, ok := p.Release(context.Background(), lease.Handle); !ok {
		t.Fatal("Release did not find the lease")
	}
}

func TestProvisionRejectsNonLoopback(t *testing.T) {
	var called atomic.Bool
	p := New(testConfig(), func(context.Context, string) (service.Service, error) {
		called.Store(true)
		return newFakeService(testAddr{host: "abc123"}), nil
	})

	_, err := p.Provision(context.Background(), Request{Local: "10.0.0.5:80"})
	if !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("err = %v, want ErrTargetNotAllowed", err)
	}
	if called.Load() {
		t.Error("factory was called for a disallowed target")
	}
}

func TestProvisionHonoursMaxTTL(t *testing.T) {
	cfg := testConfig()
	cfg.MaxTTL = time.Hour

	p := New(cfg, staticFactory(newFakeService(testAddr{host: "abc123"})))
	before := time.Now()
	lease, err := p.Provision(context.Background(), Request{
		Local: "127.0.0.1:8080",
		TTL:   2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got := lease.ExpiresAt.Sub(before); got < 59*time.Minute || got > 61*time.Minute {
		t.Errorf("ExpiresAt is %v from now, want about 1h", got)
	}
	t.Cleanup(func() { p.Release(context.Background(), lease.Handle) })
}

func TestReleaseIsIdempotent(t *testing.T) {
	svc := newFakeService(testAddr{host: "abc123"})
	p := New(testConfig(), staticFactory(svc))

	lease, err := p.Provision(context.Background(), Request{Local: "127.0.0.1:8080"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	released, ok := p.Release(context.Background(), lease.Handle)
	if !ok {
		t.Fatal("first Release = false, want true")
	}
	if released.Handle != lease.Handle {
		t.Errorf("released handle = %q, want %q", released.Handle, lease.Handle)
	}
	if _, ok := p.Release(context.Background(), lease.Handle); ok {
		t.Fatal("second Release = true, want false")
	}
	if got := svc.closes.Load(); got != 1 {
		t.Errorf("Close called %d times, want 1", got)
	}
	if leases := p.List(); len(leases) != 0 {
		t.Errorf("List returned %d leases after release, want 0", len(leases))
	}
}

func TestLeaseExpiresAtTTL(t *testing.T) {
	svc := newFakeService(testAddr{host: "abc123"})
	p := New(testConfig(), staticFactory(svc))

	if _, err := p.Provision(context.Background(), Request{
		Local: "127.0.0.1:8080",
		TTL:   50 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		leases := p.List()
		if len(leases) == 1 && leases[0].State == StateExpired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lease did not expire, List = %+v", leases)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := svc.closes.Load(); got != 1 {
		t.Errorf("Close called %d times, want 1", got)
	}
}

func TestMaxLeases(t *testing.T) {
	var n atomic.Int32
	factory := func(context.Context, string) (service.Service, error) {
		return newFakeService(testAddr{host: fmt.Sprintf("h%d", n.Add(1))}), nil
	}
	cfg := testConfig()
	cfg.MaxLeases = 4

	p := New(cfg, factory)
	for i := 0; i < cfg.MaxLeases; i++ {
		if _, err := p.Provision(context.Background(), Request{
			Local: "127.0.0.1:8080",
			TTL:   time.Minute,
		}); err != nil {
			t.Fatalf("Provision %d: %v", i+1, err)
		}
	}

	_, err := p.Provision(context.Background(), Request{
		Local: "127.0.0.1:8080",
		TTL:   time.Minute,
	})
	if err == nil {
		t.Fatal("fifth Provision succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "max leases") {
		t.Errorf("err = %q, want it to mention max leases", err)
	}

	for _, lease := range p.List() {
		p.Release(context.Background(), lease.Handle)
	}
}

func TestLeaseURLUpdatesOnRebind(t *testing.T) {
	svc := newFakeService(testAddr{host: "abc123"})
	p := New(testConfig(), staticFactory(svc))

	lease, err := p.Provision(context.Background(), Request{
		Local: "127.0.0.1:8080",
		TTL:   time.Minute,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	svc.setAddr(testAddr{host: "def456"})

	ok := waitFor(t, 6*time.Second, func() bool {
		leases := p.List()
		return len(leases) == 1 && leases[0].URL == "https://def456.gost.run" &&
			leases[0].State == StateRebound
	})
	if !ok {
		t.Fatalf("lease did not follow the rebind, List = %+v", p.List())
	}

	if _, ok := p.Release(context.Background(), lease.Handle); !ok {
		t.Fatal("Release did not find the lease")
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func withHTTPClient(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	old := httpClient
	httpClient = &http.Client{Transport: rt, Timeout: 5 * time.Second}
	t.Cleanup(func() { httpClient = old })
}

func TestVerifyAnyStatusCountsAsReachable(t *testing.T) {
	withHTTPClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("down")),
			Header:     make(http.Header),
		}, nil
	}))

	p := New(testConfig(), staticFactory(newFakeService(testAddr{host: "abc123"})))
	lease, err := p.Provision(context.Background(), Request{
		Local:  "127.0.0.1:8080",
		Verify: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if lease.Verify == nil {
		t.Fatal("Verify is nil, want a result")
	}
	if !lease.Verify.Checked {
		t.Error("Verify.Checked = false, want true")
	}
	if got, want := lease.Verify.Status, http.StatusServiceUnavailable; got != want {
		t.Errorf("Verify.Status = %d, want %d", got, want)
	}
	t.Cleanup(func() { p.Release(context.Background(), lease.Handle) })
}

func TestVerifyTransportErrorDoesNotFailLease(t *testing.T) {
	withHTTPClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network unreachable")
	}))

	p := New(testConfig(), staticFactory(newFakeService(testAddr{host: "abc123"})))
	lease, err := p.Provision(context.Background(), Request{
		Local:  "127.0.0.1:8080",
		Verify: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if lease.URL == "" {
		t.Error("URL is empty, want the tunnel URL despite the verify failure")
	}
	if lease.Verify == nil || !lease.Verify.Checked {
		t.Fatalf("Verify = %+v, want Checked true", lease.Verify)
	}
	if lease.Verify.Status != 0 {
		t.Errorf("Verify.Status = %d, want 0 for a transport error", lease.Verify.Status)
	}
	t.Cleanup(func() { p.Release(context.Background(), lease.Handle) })
}

// TestRealFactoryBuildsService exercises the real gost wiring without touching
// the network: ParseService only constructs components; it does not dial until
// Serve runs.
func TestRealFactoryBuildsService(t *testing.T) {
	cfg := config.WispConfig{
		Relay:  "tunnel+wss://127.0.0.1:1",
		Domain: "gost.run",
	}
	factory := realServiceFactory(cfg)
	ctx := context.WithValue(context.Background(), handleKey{}, "testhandle")
	svc, err := factory(ctx, "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if svc == nil {
		t.Fatal("factory returned a nil service")
	}

	name, ok := chainNames.Load(svc)
	if !ok {
		t.Fatal("chain was not registered for the service")
	}
	if got, want := name.(string), "lease-testhandle"; got != want {
		t.Errorf("chain name = %q, want %q", got, want)
	}

	if err := svc.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	releaseReal(svc)
	if _, ok := chainNames.Load(svc); ok {
		t.Error("chain registration survived release")
	}
}

// TestLiveProvisioner publishes a local HTTP server through the real relay. It
// is opt-in so CI never depends on wisper.gost.run.
func TestLiveProvisioner(t *testing.T) {
	if os.Getenv("GOST_MCP_LIVE") != "1" {
		t.Skip("set GOST_MCP_LIVE=1 to run against the live wisp relay")
	}

	srv := newLocalHTTPServer(t)
	defer srv.Close()

	p := New(config.WispConfig{
		Relay:     config.DefaultWispRelay,
		Domain:    config.DefaultWispDomain,
		MaxTTL:    time.Hour,
		MaxLeases: 1,
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	lease, err := p.Provision(ctx, Request{
		Local:  srv.Addr().String(),
		Label:  "live-test",
		TTL:    2 * time.Minute,
		Verify: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer p.Release(context.Background(), lease.Handle)

	if !strings.HasSuffix(lease.URL, "."+config.DefaultWispDomain) {
		t.Errorf("URL = %q, want a %s host", lease.URL, config.DefaultWispDomain)
	}
	if lease.Verify == nil || !lease.Verify.Checked {
		t.Errorf("Verify = %+v, want a checked result", lease.Verify)
	}
}

// localServer is an HTTP server that exposes its bound address for the live
// wisp test.
type localServer struct {
	srv *http.Server
	ln  net.Listener
}

func (s *localServer) Addr() net.Addr { return s.ln.Addr() }
func (s *localServer) Close() error   { return s.srv.Close() }

func newLocalHTTPServer(t *testing.T) *localServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}),
	}
	go srv.Serve(ln)
	return &localServer{srv: srv, ln: ln}
}
