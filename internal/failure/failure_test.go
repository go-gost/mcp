package failure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/go-gost/mcp/internal/egress"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantStage Stage
		wantCode  string
		retryable bool
	}{
		{
			name:      "canceled",
			err:       context.Canceled,
			wantStage: StageCanceled,
			wantCode:  CodeCanceled,
		},
		{
			name:      "canceled through wrapping",
			err:       fmt.Errorf("request: %w", context.Canceled),
			wantStage: StageCanceled,
			wantCode:  CodeCanceled,
		},
		{
			name:      "deadline exceeded",
			err:       context.DeadlineExceeded,
			wantStage: StageTimeout,
			wantCode:  CodeTimeout,
			retryable: true,
		},
		{
			// Timeout wins over the DNS classification: the lookup did not
			// answer at all.
			name:      "dns timeout is a timeout",
			err:       &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true},
			wantStage: StageTimeout,
			wantCode:  CodeTimeout,
			retryable: true,
		},
		{
			name:      "nxdomain",
			err:       &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true},
			wantStage: StageResolve,
			wantCode:  CodeNXDomain,
		},
		{
			name:      "no route",
			err:       fmt.Errorf("dial: %w", egress.ErrNoRoute),
			wantStage: StageConnect,
			wantCode:  CodeNoRoute,
		},
		{
			name: "connection refused",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
			},
			wantStage: StageConnect,
			wantCode:  CodeRefused,
			retryable: true,
		},
		{
			name:      "unknown authority",
			err:       x509.UnknownAuthorityError{},
			wantStage: StageTLS,
			wantCode:  CodeTLSVerify,
		},
		{
			name:      "certificate verification",
			err:       &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
			wantStage: StageTLS,
			wantCode:  CodeTLSVerify,
		},
		{
			name:      "not a tls server",
			err:       tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
			wantStage: StageTLS,
			wantCode:  CodeTLSHandshake,
		},
		{
			name:      "tls prefixed message",
			err:       errors.New(`Get "https://example.com": tls: unexpected message`),
			wantStage: StageTLS,
			wantCode:  CodeTLSHandshake,
		},
		{
			name:      "remote tls alert",
			err:       errors.New("remote error: tls: bad certificate"),
			wantStage: StageTLS,
			wantCode:  CodeTLSHandshake,
		},
		{
			// "notls:" is not the "tls: " token; it must not be re-staged.
			name:      "notls is not tls",
			err:       errors.New("notls: this is a different protocol"),
			wantStage: StageInternal,
			wantCode:  CodeInternal,
		},
		{
			name:      "http proxy 407",
			err:       errors.New("407 Proxy Authentication Required"),
			wantStage: StageProxyAuth,
			wantCode:  CodeProxyAuthFailed,
		},
		{
			// gosocks5.ErrAuthFailure text from the SOCKS5 connector.
			name:      "socks5 auth failure",
			err:       errors.New("auth failure"),
			wantStage: StageProxyAuth,
			wantCode:  CodeProxyAuthFailed,
		},
		{
			name:      "unknown error",
			err:       errors.New("boom"),
			wantStage: StageInternal,
			wantCode:  CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.err)
			if got == nil {
				t.Fatalf("Classify(%v) = nil, want a failure", tt.err)
			}
			if got.Stage != tt.wantStage {
				t.Errorf("Stage = %q, want %q", got.Stage, tt.wantStage)
			}
			if got.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", got.Code, tt.wantCode)
			}
			if got.Retryable != tt.retryable {
				t.Errorf("Retryable = %v, want %v", got.Retryable, tt.retryable)
			}
			if got.Message == "" {
				t.Error("Message is empty, want the error text")
			}
		})
	}
}

func TestClassifyNil(t *testing.T) {
	if got := Classify(nil); got != nil {
		t.Fatalf("Classify(nil) = %+v, want nil", got)
	}
}
