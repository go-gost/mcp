package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-gost/mcp/internal/failure"
	"github.com/go-gost/mcp/internal/wisp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// defaultWispTTL is the lease lifetime when the caller omits ttl_s. The
	// provisioner still clamps it to gost_wisp.max_ttl.
	defaultWispTTL = 900 * time.Second

	// maxWispTTL bounds the tool argument before the conversion to
	// time.Duration can overflow. config validation already caps
	// gost_wisp.max_ttl at 24h, so this never shortens a configured lease.
	maxWispTTL = 24 * time.Hour
)

// wispInput is the gost_wisp tool schema. Local is required; ttl_s and verify
// default to the spec values when omitted.
type wispInput struct {
	Local  string `json:"local" jsonschema:"loopback target to publish as host:port, such as 127.0.0.1:3000; it must resolve inside the configured gost_wisp.allow list"`
	TTLS   int64  `json:"ttl_s,omitempty" jsonschema:"lease lifetime in seconds; defaults to 900 and is capped by gost_wisp.max_ttl"`
	Label  string `json:"label,omitempty" jsonschema:"free-text label for logs and the lease listing; never part of the public URL"`
	Verify *bool  `json:"verify,omitempty" jsonschema:"request the public URL once after publishing; defaults to true"`
}

// wispOutput is the published lease. expires_at is RFC3339. A publish failure
// is ok=false with a classified failure instead of a Go error.
type wispOutput struct {
	OK        bool               `json:"ok"`
	URL       string             `json:"url"`
	Handle    string             `json:"handle"`
	Local     string             `json:"local"`
	ExpiresAt string             `json:"expires_at"`
	State     string             `json:"state"`
	Verify    *wisp.VerifyResult `json:"verify,omitempty"`
	Failure   *failure.Failure   `json:"failure,omitempty"`
}

// unwispInput is the gost_unwisp tool schema.
type unwispInput struct {
	Handle string `json:"handle" jsonschema:"lease handle returned by gost_wisp"`
}

// unwispOutput reports whether the handle owned a live lease. URL is the
// released lease's last known URL, empty when the handle was unknown.
type unwispOutput struct {
	OK       bool   `json:"ok"`
	Released bool   `json:"released"`
	URL      string `json:"url"`
}

// wispTool describes gost_wisp. The description states the action and, plainly,
// that the published URL has no access control: the local service is exposed
// to anyone who learns the URL.
func wispTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "gost_wisp",
		Description: "Publish a loopback HTTP service at a public wisp URL for a bounded lease and return its handle. " +
			"The URL is public and unauthenticated: anyone who learns it can reach the local service, so the local service must authenticate its own users. " +
			"The target must resolve inside the configured gost_wisp.allow list (loopback by default), and ttl_s is capped by gost_wisp.max_ttl. " +
			"Release it early with gost_unwisp; a relay may re-bind the tunnel, so read the current URL from the gost-mcp://leases resource. " +
			"A publish failure is reported as ok=false with a failure object.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(true),
		},
	}
}

// unwispTool describes gost_unwisp. The idempotency hint matches the behaviour:
// a second release reports released=false instead of failing.
func unwispTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "gost_unwisp",
		Description: "Release a wisp lease early and close its tunnel. " +
			"It is idempotent: an unknown, expired, or already released handle returns released=false instead of an error. " +
			"Read gost-mcp://leases to find the current handles and URLs.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  true,
		},
	}
}

// handleWisp validates the arguments and asks the provisioner to publish the
// local service. Invalid arguments and a denied target are Go errors; every
// runtime publish failure is a structured ok=false result.
func (s *server) handleWisp(ctx context.Context, _ *mcp.CallToolRequest, in wispInput) (*mcp.CallToolResult, wispOutput, error) {
	if s.deps.Wisp == nil {
		return nil, wispOutput{}, fmt.Errorf("gost_wisp: publishing is not configured")
	}

	local := strings.TrimSpace(in.Local)
	if local == "" {
		return nil, wispOutput{}, fmt.Errorf("gost_wisp: local is required")
	}

	ttl, err := wispTTL(in.TTLS)
	if err != nil {
		return nil, wispOutput{}, err
	}

	verify := true
	if in.Verify != nil {
		verify = *in.Verify
	}

	lease, err := s.deps.Wisp.Provision(ctx, wisp.Request{
		Local:  local,
		Label:  strings.TrimSpace(in.Label),
		TTL:    ttl,
		Verify: verify,
	})
	if err != nil {
		if errors.Is(err, wisp.ErrTargetNotAllowed) || errors.Is(err, wisp.ErrInvalidTarget) {
			return nil, wispOutput{}, fmt.Errorf("gost_wisp: %w", err)
		}
		return nil, wispOutput{OK: false, Failure: failure.Classify(err)}, nil
	}

	return nil, wispOutput{
		OK:        true,
		URL:       lease.URL,
		Handle:    lease.Handle,
		Local:     lease.Local,
		ExpiresAt: lease.ExpiresAt.UTC().Format(time.RFC3339),
		State:     lease.State,
		Verify:    lease.Verify,
	}, nil
}

// handleUnwisp releases a handle. It never reports an unknown handle as an
// error: the caller learns that nothing was released from released=false.
func (s *server) handleUnwisp(ctx context.Context, _ *mcp.CallToolRequest, in unwispInput) (*mcp.CallToolResult, unwispOutput, error) {
	if s.deps.Wisp == nil {
		return nil, unwispOutput{}, fmt.Errorf("gost_unwisp: publishing is not configured")
	}

	handle := strings.TrimSpace(in.Handle)
	if handle == "" {
		return nil, unwispOutput{}, fmt.Errorf("gost_unwisp: handle is required")
	}

	lease, released := s.deps.Wisp.Release(ctx, handle)
	return nil, unwispOutput{OK: true, Released: released, URL: lease.URL}, nil
}

// wispTTL converts ttl_s to a duration, applying the 900 s default and a
// saturation cap that prevents an int64 multiplication overflow. A negative
// TTL is an argument error, not a silent default.
func wispTTL(seconds int64) (time.Duration, error) {
	if seconds < 0 {
		return 0, fmt.Errorf("gost_wisp: ttl_s must not be negative")
	}
	switch {
	case seconds == 0:
		return defaultWispTTL, nil
	case seconds > int64(maxWispTTL/time.Second):
		return maxWispTTL, nil
	default:
		return time.Duration(seconds) * time.Second, nil
	}
}
