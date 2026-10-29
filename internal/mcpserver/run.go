package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/run"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// runInput is the gost_run tool schema. Egress and URL are required; every
// other field is optional and documented in its jsonschema tag.
type runInput struct {
	Egress          string            `json:"egress" jsonschema:"name of the configured egress profile to send the request through"`
	URL             string            `json:"url" jsonschema:"absolute http or https URL to request"`
	Method          string            `json:"method,omitempty" jsonschema:"HTTP method; defaults to GET"`
	Headers         map[string]string `json:"headers,omitempty" jsonschema:"literal request headers; no secret indirection"`
	Body            string            `json:"body,omitempty" jsonschema:"request body, interpreted according to body_encoding"`
	BodyEncoding    string            `json:"body_encoding,omitempty" jsonschema:"body encoding: utf8 (default) or base64"`
	TimeoutMS       int64             `json:"timeout_ms,omitempty" jsonschema:"total request timeout in milliseconds; capped at 120000"`
	MaxBytes        int64             `json:"max_bytes,omitempty" jsonschema:"response body read limit in bytes; capped at 8388608"`
	FollowRedirects *bool             `json:"follow_redirects,omitempty" jsonschema:"follow up to 5 redirects; defaults to true"`
}

// runOutput is the run result plus the egress that carried it. Embedding the
// run output keeps every field of the wire contract in one place.
type runOutput struct {
	run.Output
	Egress egressRef `json:"egress"`
}

// runTool describes gost_run. The first sentence states the action and that
// the request goes through an egress profile.
func runTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "gost_run",
		Description: "Send one HTTP(S) request through an egress profile and return the status, headers, body, timings, and any classified failure. " +
			"The egress is a configured profile name, never a URL, and the request cannot fall back to a direct connection. " +
			"A non-2xx status is still a successful call; only a transport failure sets ok=false. " +
			"Discover the profile names with the gost-mcp://egress resource.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(true),
		},
	}
}

// handleRun resolves the profile, validates the arguments, and performs one
// request. Only argument and internal faults are returned as Go errors: a
// transport failure is a structured ok=false result.
func (s *server) handleRun(ctx context.Context, _ *mcp.CallToolRequest, in runInput) (*mcp.CallToolResult, runOutput, error) {
	e, ref, err := s.resolveEgress(in.Egress)
	if err != nil {
		return nil, runOutput{}, err
	}

	rawURL := strings.TrimSpace(in.URL)
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, runOutput{}, fmt.Errorf("gost_run: url must be an absolute http or https URL")
	}

	body, err := decodeRunBody(in.Body, in.BodyEncoding)
	if err != nil {
		return nil, runOutput{}, err
	}

	followRedirects := true
	if in.FollowRedirects != nil {
		followRedirects = *in.FollowRedirects
	}

	release, err := s.acquireCall()
	if err != nil {
		return nil, runOutput{}, fmt.Errorf("gost_run: %w", err)
	}
	defer release()

	out, err := run.Do(ctx, e, run.Input{
		URL:             rawURL,
		Method:          strings.TrimSpace(in.Method),
		Headers:         in.Headers,
		Body:            body,
		Timeout:         s.runTimeout(in.TimeoutMS),
		MaxBytes:        s.runMaxBytes(in.MaxBytes),
		FollowRedirects: followRedirects,
	})
	if err != nil {
		return nil, runOutput{}, fmt.Errorf("gost_run: %w", err)
	}

	// The output schema types headers as an object, so a failure must still
	// carry an empty map rather than null.
	if out.Headers == nil {
		out.Headers = map[string]string{}
	}

	return nil, runOutput{Output: out, Egress: ref}, nil
}

// decodeRunBody applies body_encoding. Plain UTF-8 is the default; base64 is
// the only binary escape hatch, and a malformed value is an argument error.
func decodeRunBody(body, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", run.EncodingUTF8:
		return []byte(body), nil
	case run.EncodingBase64:
		if body == "" {
			return nil, nil
		}
		decoded, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("gost_run: invalid base64 body: %w", err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("gost_run: unsupported body_encoding %q (want %q or %q)",
			encoding, run.EncodingUTF8, run.EncodingBase64)
	}
}

// runTimeout returns the per-call timeout: tool argument, else configured
// default, else the package default, capped at maxRunTimeout.
func (s *server) runTimeout(ms int64) time.Duration {
	d := s.cfg.Run.Timeout
	if ms > 0 {
		if ms >= maxRunTimeout.Milliseconds() {
			return maxRunTimeout
		}
		d = time.Duration(ms) * time.Millisecond
	}
	if d <= 0 {
		d = config.DefaultRunTimeout
	}
	if d > maxRunTimeout {
		d = maxRunTimeout
	}
	return d
}

// runMaxBytes returns the body read limit: tool argument, else configured
// default, else the package default, capped at maxRunMaxBytes.
func (s *server) runMaxBytes(n int64) int64 {
	v := s.cfg.Run.MaxBytes
	if n > 0 {
		v = n
	}
	if v <= 0 {
		v = config.DefaultRunMaxBytes
	}
	if v > maxRunMaxBytes {
		v = maxRunMaxBytes
	}
	return v
}
