// Package failure classifies transport errors into a stable stage and code.
//
// A failure is reported, not returned: the MCP tools describe what went wrong
// so the model can decide whether to retry, change egress, or fix the request.
package failure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"syscall"

	"github.com/go-gost/mcp/internal/egress"
)

// Stage names the operation that failed.
type Stage string

// Stages reported by Classify and the run/trace layers. The run layer
// overrides the classified stage with the operation it was performing, which
// is more precise than what the error text alone can say.
const (
	StageConfig    Stage = "config"
	StagePolicy    Stage = "policy"
	StageResolve   Stage = "resolve"
	StageConnect   Stage = "connect"
	StageProxyAuth Stage = "proxy_auth"
	StageTLS       Stage = "tls"
	StageHTTP      Stage = "http"
	StageRead      Stage = "read"
	StageTimeout   Stage = "timeout"
	StageCanceled  Stage = "canceled"
	StageInternal  Stage = "internal"
)

// Codes paired with a stage.
const (
	CodeCanceled        = "canceled"
	CodeTimeout         = "timeout"
	CodeNXDomain        = "nxdomain"
	CodeNoRoute         = "no_route"
	CodeRefused         = "refused"
	CodeTLSVerify       = "tls_verify"
	CodeTLSHandshake    = "tls_handshake"
	CodeProxyAuthFailed = "proxy_auth_failed"
	CodeInternal        = "internal"
)

// Failure is one classified error.
type Failure struct {
	Stage     Stage  `json:"stage"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Classify returns the best guess for err, or nil when err is nil.
//
// It is a fallback: an error alone cannot say which operation was running, so
// the run layer overrides Stage (and a generic code such as "internal") with
// what it was doing. For example, an EOF during the TLS handshake is
// {tls, tls_handshake}.
func Classify(err error) *Failure {
	if err == nil {
		return nil
	}

	f := classify(err)
	f.Message = err.Error()
	return f
}

func classify(err error) *Failure {
	// Cancellation first: a canceled context also reports a deadline-like
	// error through some wrappers.
	if errors.Is(err, context.Canceled) {
		return &Failure{Stage: StageCanceled, Code: CodeCanceled}
	}

	// Deadlines and socket timeouts. Checked before the DNS case because a
	// lookup that never answered is a timeout, not a name that does not exist.
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
		return &Failure{Stage: StageTimeout, Code: CodeTimeout, Retryable: true}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return &Failure{Stage: StageResolve, Code: CodeNXDomain}
	}

	if errors.Is(err, egress.ErrNoRoute) {
		return &Failure{Stage: StageConnect, Code: CodeNoRoute}
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return &Failure{Stage: StageConnect, Code: CodeRefused, Retryable: true}
	}

	// Certificate problems are a TLS stage but a distinct code: retrying the
	// same request cannot help, changing the egress or the URL can.
	if isCertificateError(err) {
		return &Failure{Stage: StageTLS, Code: CodeTLSVerify}
	}

	if isTLSMessage(err) {
		return &Failure{Stage: StageTLS, Code: CodeTLSHandshake}
	}

	if isProxyAuthError(err) {
		return &Failure{Stage: StageProxyAuth, Code: CodeProxyAuthFailed}
	}

	return &Failure{Stage: StageInternal, Code: CodeInternal}
}

// isCertificateError reports whether err is a certificate verification
// failure, including the tls.CertificateVerificationError wrapper.
func isCertificateError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return true
	}
	var roots x509.SystemRootsError
	if errors.As(err, &roots) {
		return true
	}
	var verify *tls.CertificateVerificationError
	return errors.As(err, &verify)
}

// isTLSMessage matches the "tls: " token rather than any substring containing
// "tls:". net/http wraps handshake errors in *url.Error, which prefixes the
// request ("Get \"https://...\": tls: ..."), so a token at the start or after a
// space is the shape to match; "notls:" must not be classified as TLS.
func isTLSMessage(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "tls: ") || strings.Contains(msg, " tls: ")
}

// isProxyAuthError matches the HTTP proxy status line and gosocks5's
// ErrAuthFailure text, the two shapes the gost connectors surface.
func isProxyAuthError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "proxy authentication") ||
		strings.Contains(msg, "auth failure")
}
