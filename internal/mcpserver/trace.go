package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/trace"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// traceInput is the gost_trace tool schema. Egress and target are required;
// prefix defaults to true so the caller sees cumulative chain prefixes unless
// it opts out.
type traceInput struct {
	Egress    string `json:"egress" jsonschema:"name of the configured egress profile to diagnose through"`
	Target    string `json:"target" jsonschema:"host:port, http(s) URL, udp://host:port, tls://host:port, or dns://name"`
	Mode      string `json:"mode,omitempty" jsonschema:"auto (default), tcp, udp, dns, tls, http, or https"`
	Resolver  string `json:"resolver,omitempty" jsonschema:"DNS resolver host:port for mode=dns; defaults to the first nameserver in /etc/resolv.conf"`
	Prefix    *bool  `json:"prefix,omitempty" jsonschema:"probe cumulative chain prefixes (direct, hop 0, hop 0+1, ...); defaults to true"`
	TimeoutMS int64  `json:"timeout_ms,omitempty" jsonschema:"budget for the whole trace in milliseconds; capped at 60000"`
	Payload   string `json:"payload,omitempty" jsonschema:"optional bytes to send, base64 encoded, for tcp and udp"`
	Expect    string `json:"expect,omitempty" jsonschema:"optional substring expected in the reply"`
	Identity  bool   `json:"identity,omitempty" jsonschema:"also fetch the public egress identity from the configured endpoint"`
}

// traceOutput is the report plus the egress that was traced.
type traceOutput struct {
	trace.Report
	Egress egressRef `json:"egress"`
}

// traceTool describes gost_trace. The first sentence states the action and that
// the diagnosis goes through an egress profile; the second rules out reading
// the name as a traceroute.
func traceTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "gost_trace",
		Description: "Diagnose connectivity through an egress profile stage by stage: local resolve, connect, TLS, and HTTP/read or a DNS query. " +
			"It traces cumulative chain prefixes (direct, hop 0, hop 0+1, ...), not per-hop TTL hops, and stops at the first failing prefix. " +
			"It is not a traceroute: a gost chain is a sequence of proxy hops, and per-hop timing inside one hop is not observable. " +
			"A timeout returns the prefixes that completed, with ok=false. Discover the profile names with the gost-mcp://egress resource.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(true),
		},
	}
}

// handleTrace resolves the profile, validates the arguments, takes a trace slot,
// and runs the diagnosis. Only argument and internal faults are Go errors: a
// failed diagnosis is a structured ok=false report.
func (s *server) handleTrace(ctx context.Context, _ *mcp.CallToolRequest, in traceInput) (*mcp.CallToolResult, traceOutput, error) {
	e, ref, err := s.resolveEgress(in.Egress)
	if err != nil {
		return nil, traceOutput{}, err
	}

	target := strings.TrimSpace(in.Target)
	if target == "" {
		return nil, traceOutput{}, fmt.Errorf("gost_trace: target is required")
	}

	payload, err := decodeTracePayload(in.Payload)
	if err != nil {
		return nil, traceOutput{}, err
	}

	prefix := true
	if in.Prefix != nil {
		prefix = *in.Prefix
	}

	// Bound abandoned dial goroutines and file descriptors before starting a
	// call; a full server refuses the call instead of queueing more.
	release, err := s.acquireCall()
	if err != nil {
		return nil, traceOutput{}, fmt.Errorf("gost_trace: %w", err)
	}
	defer release()

	report, err := trace.Run(ctx, e, trace.Input{
		Target:      target,
		Mode:        in.Mode,
		Resolver:    in.Resolver,
		Prefix:      prefix,
		Identity:    in.Identity,
		IdentityURL: s.cfg.Trace.IdentityURL,
		Timeout:     s.traceTimeout(in.TimeoutMS),
		Payload:     payload,
		Expect:      in.Expect,
	})
	if err != nil {
		return nil, traceOutput{}, fmt.Errorf("gost_trace: %w", err)
	}

	// The output schema types identity as an object; report "no identity
	// lookup" as an empty object rather than null.
	if report.Identity == nil {
		report.Identity = map[string]any{}
	}

	return nil, traceOutput{Report: report, Egress: ref}, nil
}

// decodeTracePayload decodes the optional base64 payload.
func decodeTracePayload(payload string) ([]byte, error) {
	if payload == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("gost_trace: invalid base64 payload: %w", err)
	}
	return decoded, nil
}

// traceTimeout returns the whole-call budget: tool argument, else configured
// default, else the package default, capped at maxTraceTimeout.
func (s *server) traceTimeout(ms int64) time.Duration {
	d := s.cfg.Trace.Timeout
	if ms > 0 {
		if ms >= maxTraceTimeout.Milliseconds() {
			return maxTraceTimeout
		}
		d = time.Duration(ms) * time.Millisecond
	}
	if d <= 0 {
		d = config.DefaultTraceTimeout
	}
	if d > maxTraceTimeout {
		d = maxTraceTimeout
	}
	return d
}
