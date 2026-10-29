package trace

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/mcp/internal/egress"
	"github.com/go-gost/mcp/internal/failure"
	"golang.org/x/net/dns/dnsmessage"
)

// maxDNSBytes bounds one UDP response. A larger answer must come over TCP.
const maxDNSBytes = 4096

// DNS failures that are answers ("no such name", "no records") rather than
// transport errors.
var (
	errDNSNXDomain = errors.New("dns: no such name")
	errDNSNoData   = errors.New("dns: no A or AAAA answers")
)

// runDNS queries the resolver through the egress. This answers what the exit
// sees for a name, which is a different question from the local resolve stage.
func runDNS(ctx context.Context, e *egress.Egress, p plan) diagnosis {
	start := time.Now()

	route, err := e.Route(ctx, "udp", p.resolver)
	if err != nil {
		f := classifyOp(failure.StageConnect, err)
		return diagnosis{
			stages:  []Stage{{Name: "connect", MS: elapsedMS(start), Error: f}},
			failure: f,
			stage:   "connect",
		}
	}

	d := diagnosis{servedBy: routeLastHopNames(route, e.HopConfigs())}
	start = time.Now()

	answers, err := resolveVia(ctx, route, p.resolver, p.dnsName)
	detail := map[string]any{"resolver": p.resolver, "name": p.dnsName}
	if err != nil {
		f := classifyOp(failure.StageResolve, err)
		switch {
		case errors.Is(err, errDNSNXDomain):
			f = &failure.Failure{Stage: failure.StageResolve, Code: failure.CodeNXDomain, Message: err.Error()}
		case errors.Is(err, errDNSNoData):
			f = &failure.Failure{Stage: failure.StageResolve, Code: codeNoData, Message: err.Error()}
		}
		d.stages = []Stage{{Name: "dns", MS: elapsedMS(start), Detail: detail, Error: f}}
		d.failure = f
		d.stage = "dns"
		return d
	}

	detail["answers"] = answers
	d.ok = true
	d.stages = []Stage{{Name: "dns", OK: true, MS: elapsedMS(start), Detail: detail}}
	return d
}

// resolveVia sends an A and an AAAA query through route and returns the
// addresses both answers contained.
func resolveVia(ctx context.Context, route chain.Route, resolver, name string) ([]string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil, errors.New("dns: empty name")
	}

	a, aErr := queryName(ctx, route, resolver, name, dnsmessage.TypeA)
	aaaa, aaaaErr := queryName(ctx, route, resolver, name, dnsmessage.TypeAAAA)

	if answers := dedupe(append(a, aaaa...)); len(answers) > 0 {
		return answers, nil
	}
	// Prefer a real transport error over the "name exists but has no address"
	// answers, so a timeout is never mislabelled as nodata.
	for _, err := range []error{aErr, aaaaErr} {
		if err != nil && !errors.Is(err, errDNSNXDomain) {
			return nil, err
		}
	}
	if errors.Is(aErr, errDNSNXDomain) && errors.Is(aaaaErr, errDNSNXDomain) {
		return nil, errDNSNXDomain
	}
	return nil, errDNSNoData
}

// queryName runs one query over UDP and retries over TCP when it is truncated.
func queryName(ctx context.Context, route chain.Route, resolver, name string, typ dnsmessage.Type) ([]string, error) {
	query, err := buildDNSQuery(name, typ)
	if err != nil {
		return nil, err
	}

	resp, truncated, err := exchangeDNS(ctx, route, resolver, query, false)
	if err != nil {
		return nil, err
	}
	if truncated {
		resp, _, err = exchangeDNS(ctx, route, resolver, query, true)
		if err != nil {
			return nil, err
		}
	}

	return parseDNSResponse(resp)
}

func buildDNSQuery(name string, typ dnsmessage.Type) ([]byte, error) {
	fqdn := name
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	n, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("dns: invalid name %q: %w", name, err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               uint16(time.Now().UnixNano()),
		RecursionDesired: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// exchangeDNS sends one query and reads one response. It returns the raw
// response and whether the UDP answer was truncated.
func exchangeDNS(ctx context.Context, route chain.Route, resolver string, query []byte, tcp bool) ([]byte, bool, error) {
	network := "udp"
	if tcp {
		network = "tcp"
	}

	conn, err := dialRoute(ctx, route, network, resolver)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	setDeadline(ctx, conn)

	if tcp {
		if len(query) > 0xffff {
			return nil, false, errors.New("dns: query too large")
		}
		framed := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
		copy(framed[2:], query)
		if _, err := conn.Write(framed); err != nil {
			return nil, false, err
		}

		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, false, err
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n == 0 {
			return nil, false, errors.New("dns: empty TCP response")
		}
		resp := make([]byte, n)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, false, err
		}
		return resp, false, nil
	}

	if _, err := conn.Write(query); err != nil {
		return nil, false, err
	}
	buf := make([]byte, maxDNSBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	if n < 12 {
		return nil, false, fmt.Errorf("dns: short response (%d bytes)", n)
	}

	// Read the TC bit from the header rather than unpacking: a truncated
	// message may not decode, which is exactly what TC is telling us.
	truncated := binary.BigEndian.Uint16(buf[2:4])&0x0200 != 0
	return buf[:n], truncated, nil
}

func parseDNSResponse(buf []byte) ([]string, error) {
	var m dnsmessage.Message
	if err := m.Unpack(buf); err != nil {
		return nil, fmt.Errorf("dns: unpack response: %w", err)
	}
	if m.RCode == dnsmessage.RCodeNameError {
		return nil, errDNSNXDomain
	}
	if m.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("dns: %s", m.RCode)
	}

	p := dnsmessage.Parser{}
	if _, err := p.Start(buf); err != nil {
		return nil, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return nil, err
	}

	out := []string{}
	for _, answer := range answers {
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, net.IP(body.A[:]).String())
		case *dnsmessage.AAAAResource:
			out = append(out, net.IP(body.AAAA[:]).String())
		}
	}
	return out, nil
}

func dedupe(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// resolverAddress normalizes an explicit resolver, or reads the first
// nameserver from /etc/resolv.conf. No public resolver is hardcoded.
func resolverAddress(resolver string) (string, error) {
	if strings.TrimSpace(resolver) == "" {
		return defaultResolver()
	}
	return withPort(resolver, dnsDefaultPort)
}

func defaultResolver() (string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("trace: read /etc/resolv.conf: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "nameserver") {
			return withPort(fields[1], dnsDefaultPort)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("trace: /etc/resolv.conf has no nameserver")
}
