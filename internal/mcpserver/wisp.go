package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-gost/mcp/internal/failure"
	"github.com/go-gost/mcp/internal/wisp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// defaultWispTTL is the lease lifetime when the caller omits ttl_s. The
	// provisioner still clamps it to gost-wisp.max_ttl.
	defaultWispTTL = 900 * time.Second

	// maxWispTTL bounds the tool argument before the conversion to
	// time.Duration can overflow. config validation already caps
	// gost-wisp.max_ttl at 24h, so this never shortens a configured lease.
	maxWispTTL = 24 * time.Hour

	// maxWispLabel caps the free-text label so a model cannot grow the lease
	// store or operator log lines without bound.
	maxWispLabel = 128
)

// wispInput is the gost-wisp tool schema. Local is required; ttl_s and verify
// default to the spec values when omitted.
type wispInput struct {
	Local  string `json:"local" jsonschema:"loopback target to publish as host:port, such as 127.0.0.1:3000; it must resolve inside the configured gost-wisp.allow list"`
	TTLS   int64  `json:"ttl_s,omitempty" jsonschema:"lease lifetime in seconds; defaults to 900 and is capped by gost-wisp.max_ttl"`
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

// unwispInput is the gost-unwisp tool schema.
type unwispInput struct {
	Handle string `json:"handle" jsonschema:"lease handle returned by gost-wisp"`
}

// unwispOutput reports whether the handle owned a live lease. URL is the
// released lease's last known URL, empty when the handle was unknown.
type unwispOutput struct {
	OK       bool   `json:"ok"`
	Released bool   `json:"released"`
	URL      string `json:"url"`
}

// wispTool describes gost-wisp. The description states the action and, plainly,
// that the published URL has no access control: the local service is exposed
// to anyone who learns the URL.
func wispTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "gost-wisp",
		Description: "Publish a loopback HTTP service at a public wisp URL for a bounded lease and return its handle. " +
			"The URL is public and unauthenticated: anyone who learns it can reach the local service, so the local service must authenticate its own users. " +
			"The target must resolve inside the configured gost-wisp.allow list (loopback by default), and ttl_s is capped by gost-wisp.max_ttl. " +
			"Release it early with gost-unwisp; a relay may re-bind the tunnel, so read the current URL from the gost-mcp://leases resource. " +
			"A publish failure is reported as ok=false with a failure object.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(true),
		},
	}
}

// unwispTool describes gost-unwisp. The idempotency hint matches the behaviour:
// a second release reports released=false instead of failing.
func unwispTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "gost-unwisp",
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
		return nil, wispOutput{}, fmt.Errorf("gost-wisp: publishing is not configured")
	}

	local := strings.TrimSpace(in.Local)
	if local == "" {
		return nil, wispOutput{}, fmt.Errorf("gost-wisp: local is required")
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
		Label:  capLabel(in.Label),
		TTL:    ttl,
		Verify: verify,
	})
	if err != nil {
		if errors.Is(err, wisp.ErrTargetNotAllowed) || errors.Is(err, wisp.ErrInvalidTarget) {
			return nil, wispOutput{}, fmt.Errorf("gost-wisp: %w", err)
		}
		return nil, wispOutput{OK: false, Failure: failure.Classify(err)}, nil
	}

	// The publication record is the operator's audit trail: label, target,
	// URL, handle, and expiry, and nothing from the egress configuration.
	s.logger().Info("wisp: published lease",
		"label", lease.Label,
		"target", lease.Local,
		"url", lease.URL,
		"handle", lease.Handle,
		"expires_at", lease.ExpiresAt.UTC().Format(time.RFC3339),
	)

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
		return nil, unwispOutput{}, fmt.Errorf("gost-unwisp: publishing is not configured")
	}

	handle := strings.TrimSpace(in.Handle)
	if handle == "" {
		return nil, unwispOutput{}, fmt.Errorf("gost-unwisp: handle is required")
	}

	lease, released := s.deps.Wisp.Release(ctx, handle)
	// An expired or dead lease is already gone: the provisioner retains the
	// record for reporting and reports the handle as found, but nothing is
	// left to revoke.
	released = released && lease.State != wisp.StateExpired && lease.State != wisp.StateDead

	s.logger().Info("wisp: released lease",
		"handle", handle,
		"url", lease.URL,
		"released", released,
	)

	return nil, unwispOutput{OK: true, Released: released, URL: lease.URL}, nil
}

// wispTTL converts ttl_s to a duration, applying the 900 s default and a
// saturation cap that prevents an int64 multiplication overflow. A negative
// TTL is an argument error, not a silent default.
func wispTTL(seconds int64) (time.Duration, error) {
	if seconds < 0 {
		return 0, fmt.Errorf("gost-wisp: ttl_s must not be negative")
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

// capLabel trims the label and truncates it to maxWispLabel bytes without
// splitting a UTF-8 sequence.
func capLabel(label string) string {
	label = strings.TrimSpace(label)
	if len(label) <= maxWispLabel {
		return label
	}
	cut := maxWispLabel
	for cut > 0 && !utf8.RuneStart(label[cut]) {
		cut--
	}
	return label[:cut]
}
