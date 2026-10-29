package trace

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/egress"
	"github.com/go-gost/mcp/internal/failure"
	"github.com/go-gost/mcp/internal/testutil"
	xconfig "github.com/go-gost/x/config"
	"golang.org/x/net/dns/dnsmessage"
)

// directEgress builds the explicit no-proxy egress.
func directEgress(t *testing.T) *egress.Egress {
	t.Helper()

	e, err := egress.Build(&config.EgressProfile{Name: "direct", Chain: []string{}})
	if err != nil {
		t.Fatalf("build direct egress: %v", err)
	}
	return e
}

// chainEgress builds a one-node-per-hop egress from the given proxy addresses.
func chainEgress(t *testing.T, addrs ...string) *egress.Egress {
	t.Helper()

	hops := make([]*xconfig.HopConfig, len(addrs))
	for i, addr := range addrs {
		hops[i] = &xconfig.HopConfig{
			Name: fmt.Sprintf("hop-%d", i),
			Nodes: []*xconfig.NodeConfig{{
				Name: fmt.Sprintf("%c", 'a'+i),
				Addr: addr,
			}},
		}
	}
	e, err := egress.Build(&config.EgressProfile{Name: "chain", Hops: hops})
	if err != nil {
		t.Fatalf("build chain egress: %v", err)
	}
	return e
}

// startTarget runs an HTTP server and returns its host:port address.
func startTarget(t *testing.T) (string, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "trace-test")
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), srv
}

func findStage(t *testing.T, rep Report, name string) Stage {
	t.Helper()

	for _, st := range rep.Stages {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("stage %q not found in %+v", name, rep.Stages)
	return Stage{}
}

func TestTraceStagesTLSFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	rep, err := Run(context.Background(), directEgress(t), Input{
		Target:  ln.Addr().String(),
		Mode:    "tls",
		Prefix:  true,
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.OK {
		t.Fatalf("OK = true, want false; stages = %+v", rep.Stages)
	}
	if got := rep.Mode; got != "tls" {
		t.Errorf("Mode = %q, want tls", got)
	}

	if st := findStage(t, rep, "resolve"); !st.OK {
		t.Errorf("resolve stage = %+v, want ok", st)
	}
	if st := findStage(t, rep, "connect"); !st.OK {
		t.Errorf("connect stage = %+v, want ok", st)
	}
	tlsStage := findStage(t, rep, "tls")
	if tlsStage.OK {
		t.Fatalf("tls stage = %+v, want a handshake failure", tlsStage)
	}
	if tlsStage.Error == nil {
		t.Fatal("tls stage error = nil, want a classified failure")
	}
	if tlsStage.Error.Stage != failure.StageTLS {
		t.Errorf("tls error stage = %q, want %q", tlsStage.Error.Stage, failure.StageTLS)
	}
	if tlsStage.Error.Code != failure.CodeTLSHandshake {
		t.Errorf("tls error code = %q, want %q", tlsStage.Error.Code, failure.CodeTLSHandshake)
	}

	if rep.Failure == nil {
		t.Fatal("Failure = nil, want the TLS handshake failure")
	}
	if rep.Failure.Stage != failure.StageTLS || rep.Failure.Code != failure.CodeTLSHandshake {
		t.Errorf("Failure = %+v, want {tls, tls_handshake}", rep.Failure)
	}
	if rep.Attribution == nil {
		t.Fatal("Attribution = nil, want the failing prefix")
	}
	if got := rep.Attribution.Path; len(got) != 1 || got[0] != "direct" {
		t.Errorf("Attribution.Path = %v, want [direct]", got)
	}
	if len(rep.Prefixes) != 1 || rep.Prefixes[0].Path[0] != "direct" || !rep.Prefixes[0].OK {
		t.Errorf("Prefixes = %+v, want one successful direct probe", rep.Prefixes)
	}
}

// TestTracePrefixAttribution pins the honest attribution rule: the first
// failing cumulative prefix is reported, not a guess at a per-hop TTL.
func TestTracePrefixAttribution(t *testing.T) {
	target, _ := startTarget(t)
	proxyA := testutil.NewHTTPProxy(t)
	proxyB := testutil.NewHTTPProxy(t, target)

	rep, err := Run(context.Background(), chainEgress(t, proxyA, proxyB), Input{
		Target:  target,
		Mode:    "tcp",
		Prefix:  true,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.OK {
		t.Fatalf("OK = true, want false; B denies the target")
	}
	if len(rep.Prefixes) != 3 {
		t.Fatalf("Prefixes = %+v, want direct + two cumulative prefixes", rep.Prefixes)
	}

	if got := rep.Prefixes[0]; !got.OK || !samePath(got.Path, []string{"direct"}) {
		t.Errorf("prefixes[0] = %+v, want the direct probe to succeed", got)
	}
	if got := rep.Prefixes[1]; !got.OK || !samePath(got.Path, []string{"hop-0"}) {
		t.Errorf("prefixes[1] = %+v, want the first hop to succeed", got)
	} else if !samePath(got.ServedBy, []string{"a"}) {
		t.Errorf("prefixes[1].ServedBy = %v, want [a]", got.ServedBy)
	}
	if got := rep.Prefixes[2]; got.OK || !samePath(got.Path, []string{"hop-0", "hop-1"}) {
		t.Errorf("prefixes[2] = %+v, want the full chain to fail", got)
	} else {
		if got.Stage != "connect" {
			t.Errorf("prefixes[2].Stage = %q, want connect", got.Stage)
		}
		if got.Code == "" {
			t.Error("prefixes[2].Code = empty, want the classified code")
		}
		if !samePath(got.ServedBy, []string{"b"}) {
			t.Errorf("prefixes[2].ServedBy = %v, want [b]", got.ServedBy)
		}
	}

	if rep.Attribution == nil {
		t.Fatal("Attribution = nil, want the first failing prefix")
	}
	if !samePath(rep.Attribution.Path, []string{"hop-0", "hop-1"}) {
		t.Errorf("Attribution.Path = %v, want [hop-0 hop-1]", rep.Attribution.Path)
	}
	if rep.Attribution.Stage != "connect" {
		t.Errorf("Attribution.Stage = %q, want connect", rep.Attribution.Stage)
	}
}

// TestTraceNoRoute pins Review Focus #1: a hop that selects no node must fail
// with no_route, never fall back to a direct dial or send payload.
func TestTraceNoRoute(t *testing.T) {
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

	e, err := egress.Build(&config.EgressProfile{
		Name: "broken",
		Hops: []*xconfig.HopConfig{
			{Name: "hop-0", Nodes: []*xconfig.NodeConfig{}},
		},
	})
	if err != nil {
		t.Fatalf("build egress: %v", err)
	}

	rep, err := Run(context.Background(), e, Input{
		Target:  ln.Addr().String(),
		Mode:    "tcp",
		Prefix:  false,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.OK {
		t.Fatal("OK = true, want false")
	}
	if rep.Failure == nil {
		t.Fatal("Failure = nil, want a no-route failure")
	}
	if rep.Failure.Code != failure.CodeNoRoute {
		t.Errorf("Failure.Code = %q, want %q", rep.Failure.Code, failure.CodeNoRoute)
	}
	if rep.Failure.Stage != failure.StageConnect {
		t.Errorf("Failure.Stage = %q, want %q", rep.Failure.Stage, failure.StageConnect)
	}

	select {
	case <-accepted:
		t.Fatal("the target accepted a connection; an empty route must not dial")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTraceHTTPStatus(t *testing.T) {
	target, _ := startTarget(t)

	rep, err := Run(context.Background(), directEgress(t), Input{
		Target:  "http://" + target + "/",
		Mode:    "http",
		Prefix:  false,
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("OK = false, failure = %+v", rep.Failure)
	}
	if rep.Failure != nil {
		t.Errorf("Failure = %+v, want nil", rep.Failure)
	}
	if rep.Mode != "http" {
		t.Errorf("Mode = %q, want http", rep.Mode)
	}

	st := findStage(t, rep, "http")
	if !st.OK {
		t.Fatalf("http stage = %+v, want ok", st)
	}
	if got := st.Detail["status"]; got != http.StatusOK {
		t.Errorf("http detail status = %v (%T), want 200", got, got)
	}
	if got := st.Detail["server"]; got != "trace-test" {
		t.Errorf("http detail server = %v, want trace-test", got)
	}
}

func TestTraceDNSThroughEgress(t *testing.T) {
	resolver := startDNSServer(t)

	rep, err := Run(context.Background(), directEgress(t), Input{
		Target:   "dns://example.invalid",
		Mode:     "dns",
		Resolver: resolver,
		Prefix:   false,
		Timeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("OK = false, failure = %+v", rep.Failure)
	}
	if rep.Mode != "dns" {
		t.Errorf("Mode = %q, want dns", rep.Mode)
	}

	st := findStage(t, rep, "dns")
	if !st.OK {
		t.Fatalf("dns stage = %+v, want ok", st)
	}
	answers, ok := st.Detail["answers"].([]string)
	if !ok {
		t.Fatalf("dns detail answers = %v (%T), want []string", st.Detail["answers"], st.Detail["answers"])
	}
	if !containsString(answers, "1.2.3.4") {
		t.Errorf("dns answers = %v, want 1.2.3.4", answers)
	}
	if got := st.Detail["resolver"]; got != resolver {
		t.Errorf("dns detail resolver = %v, want %v", got, resolver)
	}
}

func TestTraceTimeoutReturnsPartial(t *testing.T) {
	target, _ := startTarget(t)
	proxyA := testutil.NewHTTPProxy(t)
	blackholed := startBlackhole(t)

	start := time.Now()
	rep, err := Run(context.Background(), chainEgress(t, proxyA, blackholed), Input{
		Target:  target,
		Mode:    "tcp",
		Prefix:  true,
		Timeout: 100 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Run took %v, want the 100ms budget to bound it", elapsed)
	}
	if rep.OK {
		t.Fatal("OK = true, want false")
	}
	if rep.Failure == nil {
		t.Fatal("Failure = nil, want a timeout failure")
	}
	if rep.Failure.Stage != failure.StageTimeout || rep.Failure.Code != failure.CodeTimeout {
		t.Errorf("Failure = %+v, want {timeout, timeout}", rep.Failure)
	}
	if len(rep.Prefixes) == 0 {
		t.Fatal("Prefixes = empty, want the completed prefixes kept")
	}

	// The prefixes that finished before the budget ran out are kept.
	var succeeded int
	for _, p := range rep.Prefixes {
		if p.OK {
			succeeded++
		}
	}
	if succeeded == 0 {
		t.Errorf("Prefixes = %+v, want at least one completed successful prefix", rep.Prefixes)
	}
	last := rep.Prefixes[len(rep.Prefixes)-1]
	if last.OK {
		t.Errorf("last prefix = %+v, want the blackholed hop to fail", last)
	}
	if last.Code != failure.CodeTimeout {
		t.Errorf("last prefix code = %q, want timeout", last.Code)
	}
}

// TestTraceLabelsLocalResolveAsInformational pins Review Focus #5: the target
// name is resolved at the exit. A local nxdomain must not abort the trace when
// the proxy can still reach the name.
func TestTraceLabelsLocalResolveAsInformational(t *testing.T) {
	target, _ := startTarget(t)
	proxyAddr := testutil.NewHTTPProxyRewriting(t, target)

	e, err := egress.Build(&config.EgressProfile{
		Name:  "via-proxy",
		Chain: []string{"http://" + proxyAddr},
	})
	if err != nil {
		t.Fatalf("build egress: %v", err)
	}

	rep, err := Run(context.Background(), e, Input{
		Target:  "name-that-does-not-resolve.invalid:80",
		Mode:    "http",
		Prefix:  false,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("OK = false, failure = %+v; the exit must resolve the target name", rep.Failure)
	}

	resolve := findStage(t, rep, "resolve")
	if resolve.OK {
		t.Fatalf("resolve stage = %+v, want the local nxdomain recorded", resolve)
	}
	if resolve.Error == nil || resolve.Error.Code != failure.CodeNXDomain {
		t.Errorf("resolve error = %+v, want nxdomain", resolve.Error)
	}
	if got := resolve.Detail["local"]; got != true {
		t.Errorf("resolve detail local = %v, want true", got)
	}
	if st := findStage(t, rep, "connect"); !st.OK {
		t.Errorf("connect stage = %+v, want ok", st)
	}
	if st := findStage(t, rep, "http"); !st.OK {
		t.Errorf("http stage = %+v, want ok", st)
	}
}

func TestTraceIdentityReportsEndpoint(t *testing.T) {
	idSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"ip":      "203.0.113.7",
			"country": "JP",
			"asn":     "AS64500",
			"asn_org": "Example Networks",
		})
	}))
	t.Cleanup(idSrv.Close)

	rep, err := Run(context.Background(), directEgress(t), Input{
		Target:      idSrv.URL,
		Mode:        "http",
		Prefix:      false,
		Timeout:     3 * time.Second,
		Identity:    true,
		IdentityURL: idSrv.URL,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("OK = false, failure = %+v", rep.Failure)
	}
	if rep.Failure != nil {
		t.Errorf("Failure = %+v, want nil", rep.Failure)
	}
	if got := rep.Identity["ip"]; got != "203.0.113.7" {
		t.Errorf("identity ip = %v, want 203.0.113.7", got)
	}
	if got := rep.Identity["country"]; got != "JP" {
		t.Errorf("identity country = %v, want JP", got)
	}
	if got := rep.Identity["asn"]; got != "AS64500" {
		t.Errorf("identity asn = %v, want AS64500", got)
	}
	if got := rep.Identity["org"]; got != "Example Networks" {
		t.Errorf("identity org = %v, want Example Networks", got)
	}
}

// TestTraceIdentityFailureDoesNotMask pins that an optional identity lookup is
// never allowed to turn a successful diagnosis into a failure.
func TestTraceIdentityFailureDoesNotMask(t *testing.T) {
	target, _ := startTarget(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	rep, err := Run(context.Background(), directEgress(t), Input{
		Target:      "http://" + target + "/",
		Mode:        "http",
		Prefix:      false,
		Timeout:     3 * time.Second,
		Identity:    true,
		IdentityURL: "http://" + deadAddr + "/",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("OK = false, failure = %+v; identity must not mask a good diagnosis", rep.Failure)
	}
	if rep.Failure == nil {
		t.Fatal("Failure = nil, want the identity error recorded")
	}
	if rep.Identity != nil {
		t.Errorf("Identity = %+v, want nil when the lookup failed", rep.Identity)
	}
}

func TestTraceTCPPayloadAndExpect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				if string(buf) == "PING" {
					io.WriteString(conn, "PONG")
				}
			}()
		}
	}()

	rep, err := Run(context.Background(), directEgress(t), Input{
		Target:  ln.Addr().String(),
		Mode:    "tcp",
		Prefix:  false,
		Timeout: 2 * time.Second,
		Payload: []byte("PING"),
		Expect:  "PONG",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("OK = false, failure = %+v", rep.Failure)
	}
	st := findStage(t, rep, "read")
	if !st.OK {
		t.Fatalf("read stage = %+v, want ok", st)
	}
	if got := st.Detail["expect"]; got != true {
		t.Errorf("read detail expect = %v, want true", got)
	}
	if got := st.Detail["reply"]; got != "PONG" {
		t.Errorf("read detail reply = %v, want PONG", got)
	}
}

// TestTraceDNSTruncatedRetriesTCP pins the TC fallback: a UDP answer with the
// truncated bit set is retried over TCP through the same route.
func TestTraceDNSTruncatedRetriesTCP(t *testing.T) {
	resolver := startTruncatingDNSServer(t)

	rep, err := Run(context.Background(), directEgress(t), Input{
		Target:   "dns://truncated.invalid",
		Mode:     "dns",
		Resolver: resolver,
		Prefix:   false,
		Timeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("OK = false, failure = %+v", rep.Failure)
	}
	st := findStage(t, rep, "dns")
	answers, ok := st.Detail["answers"].([]string)
	if !ok {
		t.Fatalf("dns detail answers = %v (%T), want []string", st.Detail["answers"], st.Detail["answers"])
	}
	if !containsString(answers, "5.6.7.8") {
		t.Errorf("dns answers = %v, want the TCP answer 5.6.7.8", answers)
	}
}

// startDNSServer runs a UDP DNS server that answers A queries for any name
// with 1.2.3.4 and returns NODATA for AAAA.
func startDNSServer(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}

			resp := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 req.ID,
					Response:           true,
					RecursionAvailable: true,
				},
				Questions: req.Questions,
			}
			for _, q := range req.Questions {
				if q.Type != dnsmessage.TypeA {
					continue
				}
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
				})
			}
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			pc.WriteTo(out, addr)
		}
	}()

	return pc.LocalAddr().String()
}

// startTruncatingDNSServer answers every UDP query with the truncated bit set
// and serves the real A record over TCP on the same port.
func startTruncatingDNSServer(t *testing.T) string {
	t.Helper()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns tcp: %v", err)
	}
	t.Cleanup(func() { tcpLn.Close() })

	port := tcpLn.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatalf("listen dns udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 req.ID,
					Response:           true,
					Truncated:          true,
					RecursionAvailable: true,
				},
				Questions: req.Questions,
			}
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			pc.WriteToUDP(out, addr)
		}
	}()

	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go serveDNSTCP(conn)
		}
	}()

	return pc.LocalAddr().String()
}

func serveDNSTCP(conn net.Conn) {
	defer conn.Close()

	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 {
		return
	}
	query := make([]byte, n)
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}

	var req dnsmessage.Message
	if err := req.Unpack(query); err != nil {
		return
	}
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 req.ID,
			Response:           true,
			RecursionAvailable: true,
		},
		Questions: req.Questions,
	}
	for _, q := range req.Questions {
		if q.Type != dnsmessage.TypeA {
			continue
		}
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			},
			Body: &dnsmessage.AResource{A: [4]byte{5, 6, 7, 8}},
		})
	}

	out, err := resp.Pack()
	if err != nil {
		return
	}
	framed := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(out)))
	copy(framed[2:], out)
	conn.Write(framed)
}

// startBlackhole runs a TCP listener that accepts and never writes, so a
// proxy handshake through it stalls until the caller's budget expires.
func startBlackhole(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole: %v", err)
	}

	var mu sync.Mutex
	var conns []net.Conn

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go io.Copy(io.Discard, conn)
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})

	return ln.Addr().String()
}

func samePath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
