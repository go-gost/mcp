// Package run performs one HTTP request through an egress.
//
// The request never leaves through another path: the transport has no
// environment proxy, no cookie jar, and its dialer is the egress. A transport
// error is reported as a classified failure, not a Go error; Go errors are
// reserved for invalid input and internal faults.
package run

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-gost/mcp/internal/config"
	"github.com/go-gost/mcp/internal/egress"
	"github.com/go-gost/mcp/internal/failure"
)

// maxRedirects is the number of redirects a follow-redirects request may take
// before it is reported as a failure instead of looping.
const maxRedirects = 5

// errTooManyRedirects stops a redirect loop.
var errTooManyRedirects = errors.New("too many redirects")

// codeTooManyRedirects is the failure code for a redirect chain longer than
// maxRedirects.
const codeTooManyRedirects = "too_many_redirects"

// Body encodings reported in Output.BodyEncoding.
const (
	EncodingUTF8   = "utf8"
	EncodingBase64 = "base64"
)

// Input is one request.
type Input struct {
	URL             string
	Method          string
	Headers         map[string]string
	Body            []byte
	Timeout         time.Duration
	MaxBytes        int64
	FollowRedirects bool
}

// Output is the result of one request. OK means an HTTP response was received;
// the status may still be an error status, which is an answer, not a failure.
type Output struct {
	OK           bool              `json:"ok"`
	Status       int               `json:"status"`
	StatusText   string            `json:"status_text"`
	FinalURL     string            `json:"final_url"`
	Redirects    []Redirect        `json:"redirects"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	BodyEncoding string            `json:"body_encoding"`
	Bytes        int64             `json:"bytes"`
	Truncated    bool              `json:"truncated"`
	SHA256       string            `json:"sha256"`
	Timings      Timings           `json:"timings"`
	Failure      *failure.Failure  `json:"failure"`
}

// Timings are wall-clock milliseconds. Connect is the whole dial, including
// whatever name resolution the egress performs and, through a chain, the proxy
// CONNECT round trip. Connect and TLS accumulate across dials and redirects;
// TTFB is measured to the first byte of the last response.
type Timings struct {
	ConnectMS int64 `json:"connect_ms"`
	TLSMS     int64 `json:"tls_ms"`
	TTFBMS    int64 `json:"ttfb_ms"`
	TotalMS   int64 `json:"total_ms"`
}

// Redirect is one hop a request took.
type Redirect struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
}

// Do performs the request through e.
//
// The egress resolves the target name: no local lookup happens before the
// dial, so a proxy can reach names this host cannot resolve.
func Do(ctx context.Context, e *egress.Egress, in Input) (Output, error) {
	if e == nil {
		return Output{}, errors.New("run: nil egress")
	}

	u, err := url.Parse(in.URL)
	if err != nil {
		return Output{}, fmt.Errorf("run: invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Output{}, fmt.Errorf("run: unsupported url scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return Output{}, errors.New("run: url has no host")
	}

	method := in.Method
	if method == "" {
		method = http.MethodGet
	}

	timeout := in.Timeout
	if timeout <= 0 {
		timeout = config.DefaultRunTimeout
	}
	maxBytes := in.MaxBytes
	if maxBytes <= 0 {
		maxBytes = config.DefaultRunMaxBytes
	}

	var body io.Reader
	if len(in.Body) > 0 {
		body = bytes.NewReader(in.Body)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return Output{}, fmt.Errorf("run: new request: %w", err)
	}
	for k, v := range in.Headers {
		if strings.EqualFold(k, "host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	rec := &recorder{start: time.Now()}
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: rec.tlsStart,
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			rec.tlsDone()
			rec.failedOperation(failure.StageTLS, err)
		},
		GotFirstResponseByte: rec.gotFirstByte,
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	tr := &http.Transport{
		// The egress is the only egress: never consult HTTP_PROXY.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Time the whole dial rather than the TCP connect: the target
			// name is resolved by the exit, and through a chain the proxy
			// CONNECT round trip happens here too. httptrace's
			// ConnectStart/ConnectDone see only the TCP connect to the proxy
			// (after local resolution), so they would hide that time.
			start := time.Now()
			route, err := e.Route(ctx, network, addr)
			if err != nil {
				rec.dialDone(time.Since(start))
				return nil, err
			}
			conn, err := route.Dial(ctx, network, addr)
			rec.dialDone(time.Since(start))
			return conn, err
		},
		// One request per connection: a tool call must not inherit a stale
		// socket, and there is nothing to reuse afterwards.
		DisableKeepAlives: true,
		// Report the bytes the server sent: transparent gzip would hide the
		// real content encoding and change the hash.
		DisableCompression:    true,
		ResponseHeaderTimeout: timeout,
	}
	defer tr.CloseIdleConnections()

	redirects := make([]Redirect, 0)
	client := &http.Client{
		Transport: tr,
		// No Jar: cookies must not leak between tool calls.
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if !in.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) > maxRedirects {
				return errTooManyRedirects
			}
			// next.Response is the response that asked for this redirect;
			// next.URL is the resolved target.
			status := 0
			if next.Response != nil {
				status = next.Response.StatusCode
			}
			redirects = append(redirects, Redirect{
				Status:   status,
				Location: next.URL.String(),
			})
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		out := Output{
			OK:        false,
			Redirects: redirects,
			Timings:   rec.timings(),
		}
		if errors.Is(err, errTooManyRedirects) {
			out.Failure = &failure.Failure{
				Stage:   failure.StageHTTP,
				Code:    codeTooManyRedirects,
				Message: err.Error(),
			}
			return out, nil
		}
		out.Failure = rec.classify(err)
		return out, nil
	}
	defer resp.Body.Close()

	out := Output{
		OK:         true,
		Status:     resp.StatusCode,
		StatusText: statusText(resp.Status),
		FinalURL:   resp.Request.URL.String(),
		Redirects:  redirects,
		Headers:    filteredHeaders(resp.Header),
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, readLimit(maxBytes)))
	if err != nil {
		f := rec.classify(err)
		// A timeout stays {timeout, timeout}; only a non-timeout read error is
		// re-staged as a read failure.
		if f != nil && f.Stage != failure.StageCanceled && f.Code != failure.CodeTimeout {
			f.Stage = failure.StageRead
		}
		out.OK = false
		out.Failure = f
		out.Timings = rec.timings()
		return out, nil
	}

	if int64(len(raw)) > maxBytes {
		out.Truncated = true
		raw = raw[:maxBytes]
	}
	if isText(resp.Header.Get("Content-Type")) && utf8.Valid(raw) {
		out.Body = string(raw)
		out.BodyEncoding = EncodingUTF8
	} else {
		// A declared text type is not enough: bytes that are not UTF-8 would
		// reach the model as mojibake. Report the exact bytes instead.
		out.Body = base64.StdEncoding.EncodeToString(raw)
		out.BodyEncoding = EncodingBase64
	}
	out.Bytes = int64(len(raw))
	sum := sha256.Sum256(raw)
	out.SHA256 = hex.EncodeToString(sum[:])
	out.Timings = rec.timings()

	return out, nil
}

// readLimit returns one byte more than maxBytes so truncation is detectable.
func readLimit(maxBytes int64) int64 {
	if maxBytes == math.MaxInt64 {
		return math.MaxInt64
	}
	return maxBytes + 1
}

// statusText returns the reason phrase of a status line ("200 OK").
func statusText(status string) string {
	if i := strings.IndexByte(status, ' '); i >= 0 {
		return status[i+1:]
	}
	return ""
}

// allowedHeaders are echoed to the caller. Cookies and other session material
// stay out of the output.
var allowedHeaders = map[string]bool{
	"content-type":     true,
	"content-length":   true,
	"server":           true,
	"location":         true,
	"content-encoding": true,
	"retry-after":      true,
}

// maxExtraHeaders bounds the x-* headers echoed back so a hostile server
// cannot flood the output.
const maxExtraHeaders = 20

// filteredHeaders applies the header allowlist.
func filteredHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(allowedHeaders))
	for name := range allowedHeaders {
		if vs := h.Values(name); len(vs) > 0 {
			out[name] = strings.Join(vs, ", ")
		}
	}
	extra := 0
	for name, vs := range h {
		if extra >= maxExtraHeaders {
			break
		}
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "x-") || allowedHeaders[lower] {
			continue
		}
		out[lower] = strings.Join(vs, ", ")
		extra++
	}
	return out
}

// isText reports whether the content type is safe to display as text.
func isText(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	switch {
	case strings.HasPrefix(mt, "text/"):
		return true
	case mt == "application/json", strings.HasSuffix(mt, "+json"):
		return true
	case mt == "application/xml", mt == "text/xml", strings.HasSuffix(mt, "+xml"):
		return true
	case strings.Contains(mt, "javascript"):
		return true
	}
	return false
}

// recorder collects timings and remembers which transport operation failed.
//
// The failed operation is what lets the run layer refine failure.Classify: the
// error text alone cannot tell a TLS handshake EOF from an EOF elsewhere.
type recorder struct {
	mu sync.Mutex

	start     time.Time
	tlsAt     time.Time
	connectMS int64
	tlsMS     int64
	ttfbMS    int64

	// op is the last transport operation that failed, empty while none has.
	op failure.Stage
}

// dialDone accumulates one completed dial. The transport may dial more than
// once (redirects, happy eyeballs), so every dial counts.
func (r *recorder) dialDone(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectMS += d.Milliseconds()
}

func (r *recorder) tlsStart() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tlsAt = time.Now()
}

func (r *recorder) tlsDone() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.tlsAt.IsZero() {
		r.tlsMS += time.Since(r.tlsAt).Milliseconds()
		r.tlsAt = time.Time{}
	}
}

func (r *recorder) gotFirstByte() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ttfbMS = time.Since(r.start).Milliseconds()
}

// failedOperation remembers the last transport operation that returned an
// error. Successful operations do not overwrite it.
func (r *recorder) failedOperation(op failure.Stage, err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.op = op
}

func (r *recorder) timings() Timings {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Timings{
		ConnectMS: r.connectMS,
		TLSMS:     r.tlsMS,
		TTFBMS:    r.ttfbMS,
		TotalMS:   time.Since(r.start).Milliseconds(),
	}
}

// classify turns err into a failure, overriding the stage with the transport
// operation that failed when there is one.
func (r *recorder) classify(err error) *failure.Failure {
	f := failure.Classify(err)
	if f == nil {
		return nil
	}
	// Cancellation is reported as such: the operation did not get a chance to
	// fail on its own.
	if f.Stage == failure.StageCanceled {
		return f
	}
	// A timeout is always {timeout, timeout}, whatever stage was running
	// when the clock ran out: the caller can only retry, not re-stage it.
	if f.Code == failure.CodeTimeout {
		return f
	}

	r.mu.Lock()
	op := r.op
	r.mu.Unlock()
	if op == "" {
		return f
	}

	switch op {
	case failure.StageTLS:
		f.Stage = failure.StageTLS
		// An EOF or a closed connection during the handshake is still a
		// handshake failure, not an internal error.
		if f.Code == failure.CodeInternal {
			f.Code = failure.CodeTLSHandshake
			f.Retryable = false
		}
	case failure.StageConnect:
		f.Stage = failure.StageConnect
	}
	return f
}
