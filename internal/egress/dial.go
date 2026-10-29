package egress

import (
	"context"
	"net"

	"github.com/go-gost/core/chain"
)

// Dial bounds a route dial with ctx.
//
// gost's proxy connectors perform their CONNECT handshake inside Route.Dial
// and do not observe context cancellation once the TCP connect succeeded, so a
// blackholed proxy would otherwise block past the call budget. The dial is
// therefore run in a goroutine; if the budget expires first, the result is
// abandoned and any connection it later returns is closed. A permanently
// unresponsive peer can retain that goroutine until the OS gives up on the
// socket, which is preferable to blocking the caller indefinitely.
//
// run and trace share this helper so both bound abandoned dials the same way.
func Dial(ctx context.Context, route chain.Route, network, addr string) (net.Conn, error) {
	if route == nil {
		return nil, ErrNoRoute
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := route.Dial(ctx, network, addr)
		ch <- result{conn: conn, err: err}
	}()

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}
