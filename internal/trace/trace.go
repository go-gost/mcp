// Package trace diagnoses connectivity stage by stage through one egress.
//
// It is not a traceroute: a gost chain is a sequence of proxy hops, not a
// sequence of TTL-limited packets. The trace instead probes each cumulative
// prefix (direct, hop-0, hop-0+hop-1, ...) with a bare connect, stops at the
// first failing prefix, and then runs the complete stage sequence through the
// full chain. Prefix probes re-select nodes on every dial, so with a multi-node
// hop the probe and the final attempt can use different nodes: attribution is
// best-effort and each prefix reports the exit node names it actually used.
package trace

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/egress"
	"github.com/go-gost/mcp/internal/failure"
	xconfig "github.com/go-gost/x/config"
)

// Modes accepted by Input.Mode. ModeAuto (or an empty mode) infers the mode
// from the target scheme.
const (
	ModeAuto  = "auto"
	ModeTCP   = "tcp"
	ModeUDP   = "udp"
	ModeDNS   = "dns"
	ModeTLS   = "tls"
	ModeHTTP  = "http"
	ModeHTTPS = "https"
)

// Trace limits.
const (
	maxReadBytes   = 4096
	resolveBudget  = 2 * time.Second
	identityLimit  = 64 << 10
	dnsDefaultPort = "53"
	httpDefault    = "80"
	httpsDefault   = "443"
)

// Codes reported in addition to the failure package's stable codes.
const (
	codeUnsupported    = "unsupported"
	codeNoData         = "nodata"
	codeExpectMismatch = "expect_mismatch"
	codeIdentityURL    = "identity_url"
	codeIdentityStatus = "identity_status"
	codeIdentityDecode = "identity_decode"
)

// Input is one trace request.
type Input struct {
	Target      string
	Mode        string
	Resolver    string
	Prefix      bool
	Identity    bool
	IdentityURL string
	Timeout     time.Duration
	Payload     []byte
	Expect      string
}

// Stage is one step of the diagnosis. Resolve is informational: it describes
// what this host sees and never decides the report on its own.
type Stage struct {
	Name   string           `json:"name"`
	OK     bool             `json:"ok"`
	MS     int64            `json:"ms"`
	Detail map[string]any   `json:"detail,omitempty"`
	Error  *failure.Failure `json:"error,omitempty"`
}

// PrefixResult is one cumulative-chain probe.
type PrefixResult struct {
	Path     []string `json:"path"`
	ServedBy []string `json:"served_by"`
	OK       bool     `json:"ok"`
	MS       int64    `json:"ms"`
	Stage    string   `json:"stage,omitempty"`
	Code     string   `json:"code,omitempty"`
}

// Attribution names the prefix and stage a failure is attributed to.
type Attribution struct {
	Path     []string `json:"path"`
	ServedBy []string `json:"served_by"`
	Stage    string   `json:"stage"`
	Code     string   `json:"code"`
}

// Report is the trace result. A false OK always carries a Failure.
type Report struct {
	OK          bool             `json:"ok"`
	Target      string           `json:"target"`
	Mode        string           `json:"mode"`
	Stages      []Stage          `json:"stages"`
	Attribution *Attribution     `json:"attribution"`
	Prefixes    []PrefixResult   `json:"prefixes"`
	Identity    map[string]any   `json:"identity"`
	Failure     *failure.Failure `json:"failure"`
}

// plan is a parsed target. It is computed before any dial so invalid input is
// a Go error, not a classified transport failure.
type plan struct {
	mode     string
	network  string
	addr     string
	host     string
	path     string
	tls      bool
	resolver string
	dnsName  string
}

// Run traces in.Target through e.
//
// Timeout is a budget for the whole call, not per dial: every stage and every
// prefix probe draws from the same deadline. A timeout returns the completed
// stages and prefixes with {timeout, timeout} rather than nothing.
func Run(ctx context.Context, e *egress.Egress, in Input) (Report, error) {
	if e == nil {
		return Report{}, errors.New("trace: nil egress")
	}

	p, err := parseTarget(in.Target, in.Mode, in.Resolver)
	if err != nil {
		return Report{}, err
	}

	timeout := in.Timeout
	if timeout <= 0 {
		timeout = config.DefaultTraceTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rep := Report{
		Target:   strings.TrimSpace(in.Target),
		Mode:     p.mode,
		Stages:   []Stage{},
		Prefixes: []PrefixResult{},
	}

	// The local lookup is always informational. A proxy can resolve names
	// this host cannot, and vice versa, so its result never aborts the trace.
	rep.Stages = append(rep.Stages, runResolve(ctx, p))

	if in.Prefix {
		rep.Prefixes = probePrefixes(ctx, e, p)
	}

	diag := runStages(ctx, e, p, in)
	rep.Stages = append(rep.Stages, diag.stages...)
	rep.OK = diag.ok
	if !diag.ok {
		rep.Failure = diag.failure
		rep.Attribution = attribution(rep.Prefixes, e, diag)
	}

	// The identity lookup is charged against the same budget and is never
	// allowed to hide a diagnosis that already succeeded.
	if in.Identity && ctx.Err() == nil {
		identity, f := fetchIdentity(ctx, e, in.IdentityURL)
		if f == nil {
			rep.Identity = identity
		} else if rep.OK {
			rep.Failure = f
		}
	}

	return rep, nil
}

// diagnosis is the full-chain result, separate from the prefix probes.
type diagnosis struct {
	ok       bool
	stages   []Stage
	failure  *failure.Failure
	stage    string
	servedBy []string
}

// runStages runs connect -> tls -> http/read (or the DNS exchange) through the
// full egress.
func runStages(ctx context.Context, e *egress.Egress, p plan, in Input) diagnosis {
	if p.mode == ModeDNS {
		return runDNS(ctx, e, p)
	}

	conn, st, route := runConnect(ctx, e, p)
	d := diagnosis{
		stages:   []Stage{st},
		servedBy: routeLastHopNames(route, e.HopConfigs()),
	}
	if !st.OK {
		d.failure = st.Error
		d.stage = stageFor(st)
		return d
	}
	defer conn.Close()

	switch p.mode {
	case ModeTLS:
		_, tst := runTLS(ctx, conn, p)
		d.stages = append(d.stages, tst)
		if !tst.OK {
			d.failure = tst.Error
			d.stage = stageFor(tst)
			return d
		}
	case ModeHTTP:
		if p.tls {
			tlsConn, tst := runTLS(ctx, conn, p)
			d.stages = append(d.stages, tst)
			if !tst.OK {
				d.failure = tst.Error
				d.stage = stageFor(tst)
				return d
			}
			conn = tlsConn
		}
		hst := runHTTP(ctx, conn, p)
		d.stages = append(d.stages, hst)
		if !hst.OK {
			d.failure = hst.Error
			d.stage = stageFor(hst)
			return d
		}
	case ModeUDP, ModeTCP:
		// A bare connect is the whole TCP test. Only send/read when there is
		// something to send or check.
		if len(in.Payload) > 0 || in.Expect != "" {
			rst := runRead(ctx, conn, in)
			d.stages = append(d.stages, rst)
			if !rst.OK {
				d.failure = rst.Error
				d.stage = stageFor(rst)
				return d
			}
		}
	}

	d.ok = true
	return d
}

// runResolve records what this host sees for the target name.
func runResolve(ctx context.Context, p plan) Stage {
	start := time.Now()

	name := p.host
	if p.mode == ModeDNS {
		name = p.dnsName
	}
	detail := map[string]any{"local": true, "name": name}

	rctx, cancel := context.WithTimeout(ctx, resolveBudget)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(rctx, name)
	if err != nil {
		return Stage{
			Name:   "resolve",
			MS:     elapsedMS(start),
			Detail: detail,
			Error:  classifyOp(failure.StageResolve, err),
		}
	}
	detail["addrs"] = addrs
	return Stage{Name: "resolve", OK: true, MS: elapsedMS(start), Detail: detail}
}

// runConnect selects a route and dials the target through it. The empty-route
// error is returned before any payload is written.
func runConnect(ctx context.Context, e *egress.Egress, p plan) (net.Conn, Stage, chain.Route) {
	start := time.Now()
	detail := map[string]any{}

	route, err := e.Route(ctx, p.network, p.addr)
	if err != nil {
		f := classifyOp(failure.StageConnect, err)
		return nil, Stage{Name: "connect", MS: elapsedMS(start), Detail: detail, Error: f}, nil
	}
	detail["nodes"] = routeNodeNames(route)

	conn, err := egress.Dial(ctx, route, p.network, p.addr)
	if err != nil {
		f := classifyOp(failure.StageConnect, err)
		return nil, Stage{Name: "connect", MS: elapsedMS(start), Detail: detail, Error: f}, route
	}
	detail["local"] = conn.LocalAddr().String()
	detail["remote"] = conn.RemoteAddr().String()

	return conn, Stage{Name: "connect", OK: true, MS: elapsedMS(start), Detail: detail}, route
}

// runTLS performs the handshake and records what the exit negotiated.
func runTLS(ctx context.Context, conn net.Conn, p plan) (net.Conn, Stage) {
	start := time.Now()
	detail := map[string]any{"sni": p.host}
	setDeadline(ctx, conn)

	tlsConn := tls.Client(conn, &tls.Config{ServerName: p.host})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, Stage{
			Name:   "tls",
			MS:     elapsedMS(start),
			Detail: detail,
			Error:  classifyOp(failure.StageTLS, err),
		}
	}

	state := tlsConn.ConnectionState()
	detail["version"] = tlsVersionName(state.Version)
	if state.NegotiatedProtocol != "" {
		detail["alpn"] = state.NegotiatedProtocol
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		detail["subject"] = cert.Subject.String()
		detail["issuer"] = cert.Issuer.String()
		detail["not_after"] = cert.NotAfter.UTC().Format(time.RFC3339)
	}

	return tlsConn, Stage{Name: "tls", OK: true, MS: elapsedMS(start), Detail: detail}
}

// runHTTP sends one HEAD request over the established connection. Any status
// is an answer; only a transport error fails the stage.
//
// The request is built with http.NewRequest and written with Request.Write, so
// a target that slipped past validation cannot inject a second request through
// CRLF in the path or Host header.
func runHTTP(ctx context.Context, conn net.Conn, p plan) Stage {
	start := time.Now()
	detail := map[string]any{"path": p.path}
	setDeadline(ctx, conn)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+p.addr+p.path, nil)
	if err != nil {
		return Stage{Name: "http", MS: elapsedMS(start), Detail: detail, Error: classifyOp(failure.StageHTTP, err)}
	}
	req.Header.Set("User-Agent", "gost-mcp")
	req.Header.Set("Accept", "*/*")
	req.Close = true

	if err := req.Write(conn); err != nil {
		return Stage{Name: "http", MS: elapsedMS(start), Detail: detail, Error: classifyOp(failure.StageHTTP, err)}
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return Stage{Name: "http", MS: elapsedMS(start), Detail: detail, Error: classifyOp(failure.StageHTTP, err)}
	}
	defer resp.Body.Close()

	detail["status"] = resp.StatusCode
	if v := resp.Header.Get("Server"); v != "" {
		detail["server"] = v
	}
	if v := resp.Header.Get("Content-Type"); v != "" {
		detail["content_type"] = v
	}

	return Stage{Name: "http", OK: true, MS: elapsedMS(start), Detail: detail}
}

// runRead writes the optional payload and reads up to maxReadBytes. Without an
// Expect value the first reply chunk is enough: the connection answered.
func runRead(ctx context.Context, conn net.Conn, in Input) Stage {
	start := time.Now()
	detail := map[string]any{}
	setDeadline(ctx, conn)

	if len(in.Payload) > 0 {
		if _, err := conn.Write(in.Payload); err != nil {
			return Stage{Name: "read", MS: elapsedMS(start), Detail: detail, Error: classifyOp(failure.StageRead, err)}
		}
		detail["sent"] = len(in.Payload)
	}

	var buf []byte
	chunk := make([]byte, 1024)
	for len(buf) < maxReadBytes {
		limit := maxReadBytes - len(buf)
		if limit > len(chunk) {
			limit = len(chunk)
		}
		n, err := conn.Read(chunk[:limit])
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if in.Expect != "" && strings.Contains(string(buf), in.Expect) {
				detail["reply"] = string(buf)
				detail["bytes"] = len(buf)
				detail["expect"] = true
				return Stage{Name: "read", OK: true, MS: elapsedMS(start), Detail: detail}
			}
		}

		if err != nil {
			detail["reply"] = string(buf)
			detail["bytes"] = len(buf)

			if errors.Is(err, io.EOF) {
				if in.Expect != "" {
					return Stage{
						Name:   "read",
						MS:     elapsedMS(start),
						Detail: detail,
						Error: &failure.Failure{
							Stage:   failure.StageRead,
							Code:    codeExpectMismatch,
							Message: fmt.Sprintf("expected %q in %d bytes", in.Expect, len(buf)),
						},
					}
				}
				detail["eof"] = true
				return Stage{Name: "read", OK: true, MS: elapsedMS(start), Detail: detail}
			}
			return Stage{Name: "read", MS: elapsedMS(start), Detail: detail, Error: classifyOp(failure.StageRead, err)}
		}

		if in.Expect == "" && len(buf) > 0 {
			detail["reply"] = string(buf)
			detail["bytes"] = len(buf)
			return Stage{Name: "read", OK: true, MS: elapsedMS(start), Detail: detail}
		}
	}

	detail["reply"] = string(buf)
	detail["bytes"] = len(buf)
	if in.Expect != "" && !strings.Contains(string(buf), in.Expect) {
		return Stage{
			Name:   "read",
			MS:     elapsedMS(start),
			Detail: detail,
			Error: &failure.Failure{
				Stage:   failure.StageRead,
				Code:    codeExpectMismatch,
				Message: fmt.Sprintf("expected %q in %d bytes", in.Expect, len(buf)),
			},
		}
	}
	return Stage{Name: "read", OK: true, MS: elapsedMS(start), Detail: detail}
}

// buildEgress is egress.Build, swappable in tests so they can observe the
// temporary per-prefix egresses are closed.
var buildEgress = egress.Build

// probePrefixes dials each cumulative prefix, starting with an explicit direct
// probe, and stops at the first failure.
//
// The direct baseline is real traffic leaving from this host, so it is bounded
// to min(2s, 20% of the remaining budget). Its failure does not stop the hop
// probes: a host that cannot reach the target directly is exactly the case an
// egress exists for. Every prefix builds a fresh egress so node selection
// cannot be shared with an earlier probe; each temporary egress is closed.
func probePrefixes(ctx context.Context, e *egress.Egress, p plan) []PrefixResult {
	results := make([]PrefixResult, 0, len(e.HopConfigs())+1)

	direct, err := buildEgress(&config.EgressProfile{Name: e.Name, Chain: []string{}})
	if err != nil {
		return results
	}
	dctx, cancel := context.WithTimeout(ctx, baselineTimeout(ctx))
	pr := probeOne(dctx, direct, p, []string{"direct"}, nil)
	cancel()
	direct.Close()
	results = append(results, pr)
	if ctx.Err() != nil {
		return results
	}

	hops := e.HopConfigs()
	prefix := make([]*xconfig.HopConfig, 0, len(hops))
	path := make([]string, 0, len(hops))
	for i, hop := range hops {
		prefix = append(prefix, hop)
		path = append(path, hopName(hop, i))

		tmp, err := buildEgress(&config.EgressProfile{Name: e.Name, Hops: prefix})
		if err != nil {
			results = append(results, PrefixResult{
				Path:     append([]string(nil), path...),
				ServedBy: []string{},
				Stage:    "connect",
				Code:     failure.CodeInternal,
			})
			return results
		}

		pr = probeOne(ctx, tmp, p, append([]string(nil), path...), hop)
		tmp.Close()
		results = append(results, pr)
		if !pr.OK {
			return results
		}
	}

	return results
}

// baselineTimeout bounds the direct probe: min(2s, 20% of the remaining call
// budget). A tiny budget gets a tiny baseline rather than consuming it all.
func baselineTimeout(ctx context.Context) time.Duration {
	const maxBaseline = 2 * time.Second
	deadline, ok := ctx.Deadline()
	if !ok {
		return maxBaseline
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	if fifth := remaining / 5; fifth < maxBaseline {
		return fifth
	}
	return maxBaseline
}

// probeOne connects once through e without writing a payload.
func probeOne(ctx context.Context, e *egress.Egress, p plan, path []string, lastHop *xconfig.HopConfig) PrefixResult {
	start := time.Now()
	res := PrefixResult{Path: path, ServedBy: []string{}}

	network, addr := p.network, p.addr
	if p.mode == ModeDNS {
		network, addr = "udp", p.resolver
	}

	route, err := e.Route(ctx, network, addr)
	if err != nil {
		f := classifyOp(failure.StageConnect, err)
		res.Stage = "connect"
		res.Code = f.Code
		res.MS = elapsedMS(start)
		return res
	}
	res.ServedBy = routeLastHopNames(route, []*xconfig.HopConfig{lastHop})

	conn, err := egress.Dial(ctx, route, network, addr)
	if err != nil {
		f := classifyOp(failure.StageConnect, err)
		res.Stage = "connect"
		res.Code = f.Code
		res.MS = elapsedMS(start)
		return res
	}
	conn.Close()

	res.OK = true
	res.MS = elapsedMS(start)
	return res
}

// attribution picks the first failing prefix for a connect-stage failure and
// the full path for a later stage (TLS, HTTP, read, DNS).
func attribution(prefixes []PrefixResult, e *egress.Egress, d diagnosis) *Attribution {
	path := fullPath(e)
	served := d.servedBy
	stage := d.stage
	code := ""
	if d.failure != nil {
		code = d.failure.Code
		if d.failure.Stage == failure.StageProxyAuth {
			stage = string(failure.StageProxyAuth)
		}
	}

	if d.stage == "connect" {
		// The direct baseline is context, not a hop: attribute a connect
		// failure to the first failing hop prefix. Fall back to direct only
		// when it is the sole probe result.
		found := false
		for _, pr := range prefixes {
			if pr.OK || len(pr.Path) == 1 && pr.Path[0] == "direct" {
				continue
			}
			path = pr.Path
			served = pr.ServedBy
			stage = "connect"
			code = pr.Code
			found = true
			break
		}
		if !found && len(prefixes) == 1 && !prefixes[0].OK &&
			len(prefixes[0].Path) == 1 && prefixes[0].Path[0] == "direct" {
			path = prefixes[0].Path
			served = prefixes[0].ServedBy
			stage = "connect"
			code = prefixes[0].Code
		}
	}
	if served == nil {
		served = []string{}
	}
	if stage == "" {
		stage = string(failure.StageInternal)
	}

	return &Attribution{Path: path, ServedBy: served, Stage: stage, Code: code}
}

// fullPath names the full hop chain, or "direct" when the egress has no hops.
func fullPath(e *egress.Egress) []string {
	hops := e.HopConfigs()
	if len(hops) == 0 {
		return []string{"direct"}
	}
	path := make([]string, len(hops))
	for i, hop := range hops {
		path[i] = hopName(hop, i)
	}
	return path
}

func hopName(hop *xconfig.HopConfig, i int) string {
	if hop != nil && hop.Name != "" {
		return hop.Name
	}
	return fmt.Sprintf("hop-%d", i)
}

// routeNodeNames returns every selected node name in route order.
func routeNodeNames(route chain.Route) []string {
	out := []string{}
	if route == nil {
		return out
	}
	for _, node := range route.Nodes() {
		if node == nil || node.Name == "" {
			continue
		}
		out = append(out, node.Name)
	}
	return out
}

// routeLastHopNames returns the exit node names selected for the last hop.
// served_by answers "which node carried this prefix", so earlier proxy nodes
// are not repeated in every prefix row.
func routeLastHopNames(route chain.Route, hops []*xconfig.HopConfig) []string {
	out := []string{}
	if route == nil || len(hops) == 0 {
		return out
	}
	last := hops[len(hops)-1]
	allowed := make(map[string]struct{})
	if last != nil {
		for _, node := range last.Nodes {
			if node != nil && node.Name != "" {
				allowed[node.Name] = struct{}{}
			}
		}
	}
	for _, node := range route.Nodes() {
		if node == nil || node.Name == "" {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[node.Name]; !ok {
				continue
			}
		}
		out = append(out, node.Name)
	}
	return out
}

// classifyOp classifies err and overrides the stage with the operation that
// was running. Timeouts and cancellation keep their own stage: the caller can
// retry, and the phase is no longer the most useful fact.
func classifyOp(op failure.Stage, err error) *failure.Failure {
	f := failure.Classify(err)
	if f == nil {
		return nil
	}
	if f.Code == failure.CodeTimeout || f.Code == failure.CodeCanceled {
		return f
	}
	// A proxy 407 is more precise than the generic connect stage.
	if f.Stage == failure.StageProxyAuth {
		return f
	}
	f.Stage = op
	if f.Code == failure.CodeInternal && isUnsupported(err) {
		f.Code = codeUnsupported
		f.Retryable = false
		return f
	}
	if op == failure.StageTLS && f.Code == failure.CodeInternal {
		f.Code = failure.CodeTLSHandshake
		f.Retryable = false
	}
	return f
}

// isUnsupported recognises the "this egress cannot carry UDP" errors so they
// are not reported as an unexplained internal failure.
func isUnsupported(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"udp not supported",
		"udp is not supported",
		"not support udp",
		"unsupported network",
		"network udp is unsupported",
		"network udp unsupported",
		"tcp over udp is unsupported",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func stageFor(st Stage) string {
	if st.Error != nil && st.Error.Stage == failure.StageProxyAuth {
		return string(failure.StageProxyAuth)
	}
	return st.Name
}

func elapsedMS(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func setDeadline(ctx context.Context, conn net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "tls1.3"
	case tls.VersionTLS12:
		return "tls1.2"
	case tls.VersionTLS11:
		return "tls1.1"
	case tls.VersionTLS10:
		return "tls1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// parseTarget turns a target and mode into a dial plan.
func parseTarget(raw, mode, resolver string) (plan, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return plan{}, errors.New("trace: target is required")
	}
	if hasControl(target) {
		return plan{}, errors.New("trace: target must not contain control characters")
	}

	scheme, rest := splitScheme(target)
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return plan{}, fmt.Errorf("trace: target %q has no host", target)
	}

	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "", ModeAuto:
		switch scheme {
		case "http", "https":
			m = ModeHTTP
		case "tcp":
			m = ModeTCP
		case "udp":
			m = ModeUDP
		case "dns":
			m = ModeDNS
		case "tls":
			m = ModeTLS
		default:
			m = ModeTCP
		}
	case ModeHTTPS:
		m = ModeHTTP
	case ModeHTTP, ModeTCP, ModeUDP, ModeDNS, ModeTLS:
	default:
		return plan{}, fmt.Errorf("trace: unsupported mode %q", mode)
	}

	p := plan{mode: m}

	if m == ModeDNS {
		p.network = "udp"
		name := rest
		if i := strings.IndexAny(name, "/?"); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return plan{}, fmt.Errorf("trace: dns target %q has no name", target)
		}
		p.dnsName = name

		addr, err := resolverAddress(resolver)
		if err != nil {
			return plan{}, err
		}
		p.resolver = addr
		return p, nil
	}

	hostport := rest
	path := "/"
	if m == ModeHTTP {
		if i := strings.IndexAny(hostport, "/?"); i >= 0 {
			path = hostport[i:]
			if strings.HasPrefix(path, "?") {
				path = "/" + path
			}
			hostport = hostport[:i]
		}
	} else if i := strings.IndexByte(hostport, '/'); i >= 0 {
		hostport = hostport[:i]
	}
	if hostport == "" {
		return plan{}, fmt.Errorf("trace: target %q has no host", target)
	}

	defaultPort := ""
	switch m {
	case ModeHTTP:
		if scheme == "https" || scheme == "tls" || strings.EqualFold(strings.TrimSpace(mode), ModeHTTPS) {
			p.tls = true
			defaultPort = httpsDefault
		} else {
			defaultPort = httpDefault
		}
	case ModeTLS:
		p.tls = true
		defaultPort = httpsDefault
	}

	host, port, err := splitHostPort(hostport)
	if err != nil {
		return plan{}, fmt.Errorf("trace: invalid target %q: %w", target, err)
	}
	if host == "" {
		return plan{}, fmt.Errorf("trace: target %q has no host", target)
	}
	if port == "" {
		if defaultPort == "" {
			return plan{}, fmt.Errorf("trace: target %q has no port", target)
		}
		port = defaultPort
	}

	p.host = host
	p.addr = net.JoinHostPort(host, port)
	p.network = "tcp"
	if m == ModeUDP {
		p.network = "udp"
	}
	p.path = path
	if hasControl(p.host) || hasControl(p.path) {
		return plan{}, errors.New("trace: host and path must not contain control characters")
	}

	return p, nil
}

// hasControl reports whether s contains an ASCII control character, including
// CR and LF. Request-splitting attempts are rejected before a connection is
// opened rather than escaped later.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// splitScheme returns a known target scheme and the remainder after "://". It
// checks known prefixes instead of using url.Parse, which treats "example.com:80"
// as scheme "example.com".
func splitScheme(target string) (string, string) {
	lower := strings.ToLower(target)
	for _, scheme := range []string{"http", "https", "tcp", "tls", "udp", "dns"} {
		if strings.HasPrefix(lower, scheme+"://") {
			return scheme, target[len(scheme)+3:]
		}
	}
	return "", target
}

// splitHostPort splits host and port, tolerating a missing port and bare IPv6
// literals. An empty port means the caller applies its default.
func splitHostPort(hostport string) (string, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err == nil {
		return host, port, nil
	}
	if strings.HasPrefix(hostport, "[") {
		if strings.HasSuffix(hostport, "]") {
			return strings.Trim(hostport, "[]"), "", nil
		}
		return "", "", err
	}
	if strings.Count(hostport, ":") >= 2 {
		return hostport, "", nil
	}
	if !strings.Contains(hostport, ":") {
		return hostport, "", nil
	}
	return "", "", err
}

// withPort adds def when hostport has no port.
func withPort(hostport, def string) (string, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", errors.New("trace: empty address")
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", fmt.Errorf("trace: invalid address %q", hostport)
	}
	if port == "" {
		port = def
	}
	return net.JoinHostPort(host, port), nil
}

// fetchIdentity performs one GET through e and maps the fields the endpoint
// provides. A non-2xx answer or a malformed body is an identity failure, not a
// diagnosis failure.
func fetchIdentity(ctx context.Context, e *egress.Egress, rawURL string) (map[string]any, *failure.Failure) {
	if strings.TrimSpace(rawURL) == "" {
		rawURL = config.DefaultTraceIdentityURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, &failure.Failure{
			Stage:   failure.StageHTTP,
			Code:    codeIdentityURL,
			Message: fmt.Sprintf("trace: invalid identity url %q", rawURL),
		}
	}

	tr := &http.Transport{
		// The egress is the only egress: never consult HTTP_PROXY.
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			route, err := e.Route(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return egress.Dial(ctx, route, network, addr)
		},
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, &failure.Failure{Stage: failure.StageHTTP, Code: codeIdentityURL, Message: err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "gost-mcp")

	resp, err := (&http.Client{
		Transport: tr,
		// One identity lookup means one request: a redirect is not followed.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}).Do(req)
	if err != nil {
		return nil, failure.Classify(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &failure.Failure{
			Stage:   failure.StageHTTP,
			Code:    codeIdentityStatus,
			Message: fmt.Sprintf("trace: identity endpoint returned %s", resp.Status),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, identityLimit))
	if err != nil {
		return nil, failure.Classify(err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, &failure.Failure{Stage: failure.StageHTTP, Code: codeIdentityDecode, Message: err.Error()}
	}

	out := make(map[string]any)
	if ip, ok := raw["ip"].(string); ok && ip != "" {
		out["ip"] = ip
		out["family"] = ipFamily(ip)
	}
	if country, ok := raw["country"].(string); ok && country != "" {
		out["country"] = country
	}
	if asn, ok := raw["asn"]; ok {
		out["asn"] = asn
	}
	for _, key := range []string{"org", "asn_org"} {
		if org, ok := raw[key].(string); ok && org != "" {
			out["org"] = org
			break
		}
	}

	return out, nil
}

func ipFamily(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}
