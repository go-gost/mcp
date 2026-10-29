// Package testutil provides test fixtures shared by the mcp tests.
package testutil

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

// NewHTTPProxy starts a CONNECT-only HTTP proxy on a loopback port and returns
// its host:port address. The proxy is closed when the test ends.
//
// Targets listed in denyTargets are refused with 502, which lets a test prove
// that traffic actually went through the proxy instead of dialing directly.
func NewHTTPProxy(t *testing.T, denyTargets ...string) string {
	t.Helper()
	return startProxy(t, "", denyTargets)
}

// NewHTTPProxyRewriting starts a CONNECT-only HTTP proxy that connects every
// target to rewriteTo instead of the address in the CONNECT request.
//
// It lets a test prove the exit resolves the target name: the request can use
// a host that cannot resolve locally while the proxy forwards it to a local
// server.
func NewHTTPProxyRewriting(t *testing.T, rewriteTo string) string {
	t.Helper()
	return startProxy(t, rewriteTo, nil)
}

// startProxy serves CONNECT on a loopback port. An empty rewriteTo connects to
// the requested target.
func startProxy(t *testing.T, rewriteTo string, denyTargets []string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testutil: listen: %v", err)
	}

	deny := make(map[string]bool, len(denyTargets))
	for _, target := range denyTargets {
		deny[target] = true
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveCONNECT(conn, rewriteTo, deny)
			}()
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})

	return ln.Addr().String()
}

// serveCONNECT handles one client: it reads the CONNECT request, dials the
// target, reports success, and then relays bytes in both directions.
func serveCONNECT(conn net.Conn, rewriteTo string, deny map[string]bool) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		writeStatus(conn, http.StatusMethodNotAllowed)
		return
	}
	if deny[req.Host] {
		writeStatus(conn, http.StatusBadGateway)
		return
	}

	target := req.Host
	if rewriteTo != "" {
		target = rewriteTo
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		writeStatus(conn, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// Copy both ways; the first direction to finish tears the connection down
	// and the buffered reader keeps any payload read together with the request.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}

func writeStatus(conn net.Conn, code int) {
	io.WriteString(conn, fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code)))
}
