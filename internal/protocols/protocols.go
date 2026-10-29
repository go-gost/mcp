// Package protocols registers the gost connectors, dialers, handlers, and
// listeners an egress profile may reference.
//
// gost wires every component through side-effect registration. Importing this
// package with a blank identifier makes the registrations happen in the binary
// and in tests; without it, parsing a "socks5://" node fails with
// "unregistered connector: socks5".
package protocols

import (
	// Connectors.
	_ "github.com/go-gost/x/connector/direct"
	_ "github.com/go-gost/x/connector/http"
	_ "github.com/go-gost/x/connector/relay"
	_ "github.com/go-gost/x/connector/socks/v4"
	_ "github.com/go-gost/x/connector/socks/v5"
	_ "github.com/go-gost/x/connector/ss"
	_ "github.com/go-gost/x/connector/ss/udp"
	_ "github.com/go-gost/x/connector/tcp"
	_ "github.com/go-gost/x/connector/tunnel"

	// Dialers.
	_ "github.com/go-gost/x/dialer/direct"
	_ "github.com/go-gost/x/dialer/http2"
	_ "github.com/go-gost/x/dialer/http2/h2"
	_ "github.com/go-gost/x/dialer/mws"
	_ "github.com/go-gost/x/dialer/ssh"
	_ "github.com/go-gost/x/dialer/sshd"
	_ "github.com/go-gost/x/dialer/tcp"
	_ "github.com/go-gost/x/dialer/tls"
	_ "github.com/go-gost/x/dialer/udp"
	_ "github.com/go-gost/x/dialer/ws"

	// Handlers and listeners.
	_ "github.com/go-gost/x/handler/forward/local"
	// remote registers the rtcp/rudp/runix handlers; Task 6 publishes via
	// rtcp, which resolves to handler type "rtcp".
	_ "github.com/go-gost/x/handler/forward/remote"
	_ "github.com/go-gost/x/listener/rtcp"
)
