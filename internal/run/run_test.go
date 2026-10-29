package run

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/egress"
	"github.com/go-gost/mcp/internal/failure"
	"github.com/go-gost/mcp/internal/testutil"
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

// proxyEgress builds a one-hop egress through an HTTP proxy.
func proxyEgress(t *testing.T, proxyAddr string) *egress.Egress {
	t.Helper()

	e, err := egress.Build(&config.EgressProfile{
		Name:  "via-proxy",
		Chain: []string{"http://" + proxyAddr},
	})
	if err != nil {
		t.Fatalf("build proxy egress: %v", err)
	}
	return e
}

// startServer runs an HTTP server and returns it with its host:port address.
func startServer(t *testing.T, h http.Handler) (*httptest.Server, string) {
	t.Helper()

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, strings.TrimPrefix(srv.URL, "http://")
}

func TestRunDirectGET(t *testing.T) {
	srv, _ := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		io.WriteString(w, "hello")
	}))

	out, err := Do(context.Background(), directEgress(t), Input{
		URL:      srv.URL,
		Timeout:  5 * time.Second,
		MaxBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Fatalf("OK = false, failure = %+v", out.Failure)
	}
	if out.Failure != nil {
		t.Fatalf("Failure = %+v, want nil", out.Failure)
	}
	if out.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", out.Status)
	}
	if out.StatusText != "OK" {
		t.Errorf("StatusText = %q, want %q", out.StatusText, "OK")
	}
	if out.Body != "hello" {
		t.Errorf("Body = %q, want %q", out.Body, "hello")
	}
	if out.BodyEncoding != "utf8" {
		t.Errorf("BodyEncoding = %q, want utf8", out.BodyEncoding)
	}
	if out.Bytes != 5 {
		t.Errorf("Bytes = %d, want 5", out.Bytes)
	}
	if out.Truncated {
		t.Error("Truncated = true, want false")
	}
	if want := sha256.Sum256([]byte("hello")); out.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("SHA256 = %q, want the hash of the returned body", out.SHA256)
	}
	if out.FinalURL != srv.URL {
		t.Errorf("FinalURL = %q, want %q", out.FinalURL, srv.URL)
	}
	if out.Timings.TotalMS < 0 {
		t.Errorf("Timings.TotalMS = %d, want a non-negative duration", out.Timings.TotalMS)
	}
}

func TestRun404IsNotFailure(t *testing.T) {
	srv, _ := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))

	out, err := Do(context.Background(), directEgress(t), Input{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Fatalf("OK = false, failure = %+v", out.Failure)
	}
	if out.Failure != nil {
		t.Fatalf("Failure = %+v, want nil; an HTTP status is an answer, not a transport failure", out.Failure)
	}
	if out.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", out.Status)
	}
}

func TestRunThroughProxy(t *testing.T) {
	seen := make(chan string, 1)
	_, target := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.Path
		io.WriteString(w, "via-proxy")
	}))

	proxyAddr := testutil.NewHTTPProxy(t)
	out, err := Do(context.Background(), proxyEgress(t, proxyAddr), Input{
		URL:      "http://" + target + "/through",
		Timeout:  5 * time.Second,
		MaxBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Fatalf("OK = false, failure = %+v", out.Failure)
	}
	if out.Body != "via-proxy" {
		t.Errorf("Body = %q, want %q", out.Body, "via-proxy")
	}

	select {
	case path := <-seen:
		if path != "/through" {
			t.Errorf("server path = %q, want /through", path)
		}
	case <-time.After(time.Second):
		t.Fatal("the target server did not see the request")
	}
}

func TestRunTruncatesBody(t *testing.T) {
	body := strings.Repeat("0123456789", 10)
	srv, _ := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))

	out, err := Do(context.Background(), directEgress(t), Input{
		URL:      srv.URL,
		Timeout:  5 * time.Second,
		MaxBytes: 10,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.Truncated {
		t.Fatalf("Truncated = false, want true; body = %q", out.Body)
	}
	if len(out.Body) != 10 {
		t.Errorf("len(Body) = %d, want 10", len(out.Body))
	}
	if out.Bytes != 10 {
		t.Errorf("Bytes = %d, want 10", out.Bytes)
	}
	want := sha256.Sum256([]byte(body[:10]))
	if out.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("SHA256 = %q, want the hash of the truncated body", out.SHA256)
	}
}

func TestRunBinaryBodyIsBase64(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0xff, 0xfe}
	srv, _ := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(payload)
	}))

	out, err := Do(context.Background(), directEgress(t), Input{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if out.BodyEncoding != "base64" {
		t.Fatalf("BodyEncoding = %q, want base64", out.BodyEncoding)
	}
	if out.Body != "AAEC//4=" {
		t.Errorf("Body = %q, want %q", out.Body, "AAEC//4=")
	}
	if out.Bytes != int64(len(payload)) {
		t.Errorf("Bytes = %d, want %d", out.Bytes, len(payload))
	}
}

// TestRunInvalidUTF8FallsBackToBase64 pins that a text content type does not
// license mojibake: bytes that are not UTF-8 are returned base64-encoded, so
// the caller gets the exact bytes back.
func TestRunInvalidUTF8FallsBackToBase64(t *testing.T) {
	payload := []byte{'a', 0xe9, 'b'}
	srv, _ := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=iso-8859-1")
		w.Write(payload)
	}))

	out, err := Do(context.Background(), directEgress(t), Input{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if out.BodyEncoding != EncodingBase64 {
		t.Fatalf("BodyEncoding = %q, want base64 for non-UTF-8 text", out.BodyEncoding)
	}
	decoded, err := base64.StdEncoding.DecodeString(out.Body)
	if err != nil {
		t.Fatalf("Body is not valid base64: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Errorf("decoded body = %x, want %x", decoded, payload)
	}
	if out.Bytes != int64(len(payload)) {
		t.Errorf("Bytes = %d, want %d", out.Bytes, len(payload))
	}
}

func TestRunTimeoutIsClassified(t *testing.T) {
	srv, _ := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, "late")
	}))

	start := time.Now()
	out, err := Do(context.Background(), directEgress(t), Input{
		URL:     srv.URL,
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Do returned a Go error, want a classified failure: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Do took %v, want it bounded by the timeout", elapsed)
	}
	if out.OK {
		t.Fatal("OK = true, want false")
	}
	if out.Failure == nil {
		t.Fatal("Failure = nil, want a timeout failure")
	}
	if out.Failure.Stage != failure.StageTimeout {
		t.Errorf("Stage = %q, want %q", out.Failure.Stage, failure.StageTimeout)
	}
	if out.Failure.Code != "timeout" {
		t.Errorf("Code = %q, want timeout", out.Failure.Code)
	}
	if !out.Failure.Retryable {
		t.Error("Retryable = false, want true for a timeout")
	}
	if out.Timings.TotalMS < 40 {
		t.Errorf("Timings.TotalMS = %d, want at least the 50ms timeout", out.Timings.TotalMS)
	}
}

func TestRunRefusedIsConnect(t *testing.T) {
	// Grab a port and close it again: connecting to it is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	out, err := Do(context.Background(), directEgress(t), Input{
		URL:     "http://" + addr + "/",
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if out.OK {
		t.Fatal("OK = true, want false")
	}
	if out.Failure == nil {
		t.Fatal("Failure = nil, want a connection failure")
	}
	if out.Failure.Stage != failure.StageConnect {
		t.Errorf("Stage = %q, want %q", out.Failure.Stage, failure.StageConnect)
	}
	if out.Failure.Code != "refused" {
		t.Errorf("Code = %q, want refused", out.Failure.Code)
	}
}

func TestRunFollowsRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		default:
			io.WriteString(w, "final")
		}
	}))
	t.Cleanup(srv.Close)

	t.Run("follow", func(t *testing.T) {
		out, err := Do(context.Background(), directEgress(t), Input{
			URL:             srv.URL + "/start",
			Timeout:         5 * time.Second,
			FollowRedirects: true,
		})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if out.Status != http.StatusOK {
			t.Fatalf("Status = %d, want 200", out.Status)
		}
		if len(out.Redirects) != 1 {
			t.Fatalf("Redirects = %+v, want 1 entry", out.Redirects)
		}
		if got := out.Redirects[0].Status; got != http.StatusFound {
			t.Errorf("Redirects[0].Status = %d, want 302", got)
		}
		if !strings.HasSuffix(out.FinalURL, "/final") {
			t.Errorf("FinalURL = %q, want it to end with /final", out.FinalURL)
		}
		if out.Body != "final" {
			t.Errorf("Body = %q, want final", out.Body)
		}
	})

	t.Run("do not follow", func(t *testing.T) {
		out, err := Do(context.Background(), directEgress(t), Input{
			URL:     srv.URL + "/start",
			Timeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if out.Status != http.StatusFound {
			t.Fatalf("Status = %d, want 302", out.Status)
		}
		if len(out.Redirects) != 0 {
			t.Errorf("Redirects = %+v, want none", out.Redirects)
		}
		if !strings.HasSuffix(out.FinalURL, "/start") {
			t.Errorf("FinalURL = %q, want it to end with /start", out.FinalURL)
		}
	})
}

func TestRunRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 0
		fmt.Sscanf(r.URL.Query().Get("n"), "%d", &n)
		http.Redirect(w, r, fmt.Sprintf("/loop?n=%d", n+1), http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	out, err := Do(context.Background(), directEgress(t), Input{
		URL:             srv.URL + "/loop?n=0",
		Timeout:         5 * time.Second,
		FollowRedirects: true,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if out.OK {
		t.Fatal("OK = true, want false after too many redirects")
	}
	if out.Failure == nil || out.Failure.Code != "too_many_redirects" {
		t.Fatalf("Failure = %+v, want code too_many_redirects", out.Failure)
	}
	if len(out.Redirects) != 5 {
		t.Errorf("len(Redirects) = %d, want 5", len(out.Redirects))
	}
}

// TestRunTLSHandshakeFailure pins the stage override: the error text alone
// cannot distinguish a handshake EOF from an EOF elsewhere, so the run layer
// reports the operation it was performing.
func TestRunTLSHandshakeFailure(t *testing.T) {
	t.Run("EOF", func(t *testing.T) {
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

		out, err := Do(context.Background(), directEgress(t), Input{
			URL:     "https://" + ln.Addr().String() + "/",
			Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if out.OK {
			t.Fatal("OK = true, want false")
		}
		if out.Failure == nil {
			t.Fatal("Failure = nil, want a TLS failure")
		}
		if out.Failure.Stage != failure.StageTLS {
			t.Errorf("Stage = %q, want %q", out.Failure.Stage, failure.StageTLS)
		}
		if out.Failure.Code != "tls_handshake" {
			t.Errorf("Code = %q, want tls_handshake", out.Failure.Code)
		}
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "secure")
		}))
		// The client rejects the certificate on purpose; keep the server's
		// handshake log out of the test output.
		srv.Config.ErrorLog = log.New(io.Discard, "", 0)
		t.Cleanup(srv.Close)

		out, err := Do(context.Background(), directEgress(t), Input{
			URL:     srv.URL,
			Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if out.OK {
			t.Fatal("OK = true, want false for an untrusted certificate")
		}
		if out.Failure == nil {
			t.Fatal("Failure = nil, want a certificate failure")
		}
		if out.Failure.Stage != failure.StageTLS {
			t.Errorf("Stage = %q, want %q", out.Failure.Stage, failure.StageTLS)
		}
		if out.Failure.Code != "tls_verify" {
			t.Errorf("Code = %q, want tls_verify", out.Failure.Code)
		}
	})
}

// TestRunProxyAuthRequired pins that a proxy 407 keeps the proxy_auth stage.
// The connector performs the CONNECT inside the dial, so the run layer must
// not rewrite the more precise stage to "connect".
func TestRunProxyAuthRequired(t *testing.T) {
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
				if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
					return
				}
				io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			}()
		}
	}()

	out, err := Do(context.Background(), proxyEgress(t, ln.Addr().String()), Input{
		URL:     "http://example.com/",
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if out.OK {
		t.Fatal("OK = true, want false")
	}
	if out.Failure == nil {
		t.Fatal("Failure = nil, want a proxy auth failure")
	}
	if out.Failure.Stage != failure.StageProxyAuth {
		t.Errorf("Stage = %q, want %q", out.Failure.Stage, failure.StageProxyAuth)
	}
	if out.Failure.Code != "proxy_auth_failed" {
		t.Errorf("Code = %q, want proxy_auth_failed", out.Failure.Code)
	}
	if out.Failure.Retryable {
		t.Error("Retryable = true, want false without new credentials")
	}
}

// TestRunSucceedsWhenLocalResolveFails pins Review Focus #5: the target name is
// resolved at the exit, not locally. The proxy rewrites every CONNECT to the
// local test server, and ".invalid" never resolves, so an Ok response proves
// no local lookup happened before the dial.
func TestRunSucceedsWhenLocalResolveFails(t *testing.T) {
	seen := make(chan string, 1)
	_, target := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host
		io.WriteString(w, "rewritten")
	}))

	proxyAddr := testutil.NewHTTPProxyRewriting(t, target)

	out, err := Do(context.Background(), proxyEgress(t, proxyAddr), Input{
		URL:      "http://name-that-does-not-resolve.invalid/",
		Timeout:  5 * time.Second,
		MaxBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Fatalf("OK = false, failure = %+v; the exit must resolve the target name", out.Failure)
	}
	if out.Body != "rewritten" {
		t.Errorf("Body = %q, want rewritten", out.Body)
	}

	select {
	case host := <-seen:
		if host != "name-that-does-not-resolve.invalid" {
			t.Errorf("server Host = %q, want the unresolved name", host)
		}
	case <-time.After(time.Second):
		t.Fatal("the target server did not see the request")
	}
}

// TestRunConnectTimingIncludesProxyDial pins that connect_ms covers the CONNECT
// round trip, not just the TCP connect to the proxy: httptrace's ConnectDone
// fires before the proxy has answered, so only timing the dial closure sees
// the exit's resolution and connect work.
func TestRunConnectTimingIncludesProxyDial(t *testing.T) {
	const proxyDelay = 100 * time.Millisecond

	_, target := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "delayed-proxy")
	}))
	proxyAddr := testutil.NewHTTPProxyDelayed(t, proxyDelay, target)

	out, err := Do(context.Background(), proxyEgress(t, proxyAddr), Input{
		URL:      "http://timing.example/",
		Timeout:  5 * time.Second,
		MaxBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Fatalf("OK = false, failure = %+v", out.Failure)
	}
	// 80ms is a generous lower bound: the proxy sleeps 100ms before answering.
	if out.Timings.ConnectMS < 80 {
		t.Errorf("Timings.ConnectMS = %d, want at least 80 for a 100ms CONNECT delay", out.Timings.ConnectMS)
	}
}

// TestRunConnectTimeoutIsStageTimeout pins the contract that a timeout is
// always {timeout, timeout}: the proxy stalls the CONNECT past the request
// deadline, so the failure must not be reported as {connect, timeout}.
func TestRunConnectTimeoutIsStageTimeout(t *testing.T) {
	_, target := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "too late")
	}))
	proxyAddr := testutil.NewHTTPProxyDelayed(t, 400*time.Millisecond, target)

	out, err := Do(context.Background(), proxyEgress(t, proxyAddr), Input{
		URL:     "http://stalled.example/",
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Do returned a Go error, want a classified failure: %v", err)
	}
	if out.OK {
		t.Fatal("OK = true, want false")
	}
	if out.Failure == nil {
		t.Fatal("Failure = nil, want a timeout failure")
	}
	if out.Failure.Stage != failure.StageTimeout {
		t.Errorf("Stage = %q, want %q", out.Failure.Stage, failure.StageTimeout)
	}
	if out.Failure.Code != failure.CodeTimeout {
		t.Errorf("Code = %q, want %q", out.Failure.Code, failure.CodeTimeout)
	}
	if !out.Failure.Retryable {
		t.Error("Retryable = false, want true for a timeout")
	}
}

// TestRunProxyFailureIsConnect pins that a proxy 502 and a proxy reset are
// attributed to the egress dial, not reported as {internal, internal}. The
// classified code stays internal because the error genuinely carries no more
// detail, but the stage must say where it happened.
func TestRunProxyFailureIsConnect(t *testing.T) {
	t.Run("proxy 502", func(t *testing.T) {
		_, target := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "denied")
		}))
		proxyAddr := testutil.NewHTTPProxy(t, target)

		out, err := Do(context.Background(), proxyEgress(t, proxyAddr), Input{
			URL:     "http://" + target + "/",
			Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if out.OK {
			t.Fatal("OK = true, want false")
		}
		if out.Failure == nil {
			t.Fatal("Failure = nil, want a connect failure")
		}
		if out.Failure.Stage != failure.StageConnect {
			t.Errorf("Stage = %q, want %q (failure = %+v)", out.Failure.Stage, failure.StageConnect, out.Failure)
		}
	})

	t.Run("proxy reset", func(t *testing.T) {
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

		out, err := Do(context.Background(), proxyEgress(t, ln.Addr().String()), Input{
			URL:     "http://example.com/",
			Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if out.OK {
			t.Fatal("OK = true, want false")
		}
		if out.Failure == nil {
			t.Fatal("Failure = nil, want a connect failure")
		}
		if out.Failure.Stage != failure.StageConnect {
			t.Errorf("Stage = %q, want %q (failure = %+v)", out.Failure.Stage, failure.StageConnect, out.Failure)
		}
	})

	t.Run("unknown port", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := ln.Addr().String()
		ln.Close()

		out, err := Do(context.Background(), directEgress(t), Input{
			URL:     "http://" + addr + "/",
			Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if out.Failure == nil || out.Failure.Stage != failure.StageConnect || out.Failure.Code != failure.CodeRefused {
			t.Fatalf("Failure = %+v, want {connect, refused}", out.Failure)
		}
	})
}

// TestRecorderConnectKeepsPreciseStage pins the classification rule: the dial
// operation may only fill in a stage the classifier left as internal.
func TestRecorderConnectKeepsPreciseStage(t *testing.T) {
	rec := &recorder{}
	rec.failedOperation(failure.StageConnect, errors.New("x"))

	for _, tt := range []struct {
		err       error
		wantStage failure.Stage
		code      string
	}{
		{&net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}, failure.StageResolve, failure.CodeNXDomain},
		{errors.New("407 Proxy Authentication Required"), failure.StageProxyAuth, failure.CodeProxyAuthFailed},
		{x509.UnknownAuthorityError{}, failure.StageTLS, failure.CodeTLSVerify},
		{fmt.Errorf("dial: %w", egress.ErrNoRoute), failure.StageConnect, failure.CodeNoRoute},
	} {
		f := rec.classify(tt.err)
		if f == nil || f.Code != tt.code || f.Stage != tt.wantStage {
			t.Fatalf("classify(%v) = %+v, want {%s, %s}", tt.err, f, tt.wantStage, tt.code)
		}
	}

	// A timeout is always {timeout, timeout}, whatever the dial was doing.
	f := rec.classify(context.DeadlineExceeded)
	if f == nil || f.Stage != failure.StageTimeout || f.Code != failure.CodeTimeout {
		t.Fatalf("classify(timeout) = %+v, want {timeout, timeout}", f)
	}
}

// TestRecorderTimeoutKeepsTimeoutStage pins the stage override rule for the
// paths a network test cannot make deterministic: a timeout is always
// {timeout, timeout}, even when the clock ran out during the TLS handshake
// (the recorder's failed operation is tls).
func TestRecorderTimeoutKeepsTimeoutStage(t *testing.T) {
	rec := &recorder{}
	rec.failedOperation(failure.StageTLS, io.EOF)

	f := rec.classify(context.DeadlineExceeded)
	if f == nil {
		t.Fatal("classify returned nil, want a timeout failure")
	}
	if f.Stage != failure.StageTimeout {
		t.Errorf("Stage = %q, want %q", f.Stage, failure.StageTimeout)
	}
	if f.Code != failure.CodeTimeout {
		t.Errorf("Code = %q, want %q", f.Code, failure.CodeTimeout)
	}
	if !f.Retryable {
		t.Error("Retryable = false, want true for a timeout")
	}
}

// TestRunHeaderAllowlist pins that only the useful headers are echoed back: a
// Set-Cookie must never be relayed to the model.
func TestRunHeaderAllowlist(t *testing.T) {
	srv, _ := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server", "test-server")
		w.Header().Set("X-Request-Id", "abc123")
		w.Header().Set("Set-Cookie", "session=secret")
		io.WriteString(w, "ok")
	}))

	out, err := Do(context.Background(), directEgress(t), Input{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := out.Headers["content-type"]; got != "text/plain" {
		t.Errorf("content-type = %q, want text/plain", got)
	}
	if got := out.Headers["x-request-id"]; got != "abc123" {
		t.Errorf("x-request-id = %q, want abc123", got)
	}
	if _, ok := out.Headers["set-cookie"]; ok {
		t.Error("set-cookie leaked into the output headers")
	}
}

// TestRunIgnoresEnvironmentProxy pins that the transport never picks up
// HTTP_PROXY: the egress is the only egress.
func TestRunIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	srv, _ := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "direct")
	}))

	out, err := Do(context.Background(), directEgress(t), Input{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Fatalf("OK = false, failure = %+v; the environment proxy must be ignored", out.Failure)
	}
}

func TestRunInvalidInput(t *testing.T) {
	e := directEgress(t)

	for _, in := range []Input{
		{},
		{URL: "network-timeout://example.com/"},
		{URL: "http://"},
		{URL: "http://example.com/", Method: "BAD METHOD"},
	} {
		if _, err := Do(context.Background(), e, in); err == nil {
			t.Errorf("Do(%+v) returned no error, want an invalid-input error", in)
		}
	}
}
