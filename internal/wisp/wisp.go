// Package wisp publishes a loopback HTTP service through a wisp relay.
//
// A lease is one running gost service: a local target is exposed on the relay
// under a public label, and the provisioner tracks the lease until it is
// released or its TTL expires. Relays may re-bind a tunnel, so a lease's URL
// is not immutable: a watcher follows Addr() and reports the new URL with the
// "rebound" state.
package wisp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/service"
	"github.com/go-gost/mcp/internal/config"
)

// Lease states reported to callers.
const (
	StateActive  = "active"
	StateRebound = "rebound"
	StateExpired = "expired"
)

const (
	// bindPollInterval and bindTimeout bound the wait for the relay to
	// negotiate the public label.
	bindPollInterval = 100 * time.Millisecond
	bindTimeout      = 15 * time.Second
	// rebindInterval is how often a live tunnel's address is compared with the
	// address last reported to the caller.
	rebindInterval = 5 * time.Second
	// verifyTimeout bounds the single reachability GET.
	verifyTimeout = 5 * time.Second
	// defaultLeaseTTL mirrors the spec's 900 s default when the caller omits
	// a TTL. It is still clamped to MaxTTL.
	defaultLeaseTTL = 15 * time.Minute
	// maxExpiredRecords caps the expired-lease records kept for reporting.
	// Each expired record no longer owns a service, but retaining unbounded
	// records would still grow the store for every short-TTL lease.
	maxExpiredRecords = 32
)

// ErrTargetNotAllowed reports a target that did not resolve exclusively to an
// address inside the configured allow list.
var ErrTargetNotAllowed = errors.New("wisp: target not allowed")

// ErrInvalidTarget reports a target that is not a literal host:port with a
// numeric port in 1..65535. Such input is rejected before any resolution or
// interpolation into a gost URI, where characters such as "?", "#", "/", "@"
// or whitespace would be interpreted by gost's parser.
var ErrInvalidTarget = errors.New("wisp: invalid target")

// httpClient performs the optional reachability check. Tests replace it.
var httpClient = &http.Client{Timeout: verifyTimeout}

// Request describes one publication.
type Request struct {
	// Local is the loopback target to publish, as host:port.
	Local  string        `json:"local"`
	Label  string        `json:"label,omitempty"`
	TTL    time.Duration `json:"ttl,omitempty"`
	Verify bool          `json:"verify,omitempty"`
}

// Lease is the public view of one publication. URLs and states change after
// provisioning when the relay re-binds the tunnel.
type Lease struct {
	Handle    string        `json:"handle"`
	URL       string        `json:"url"`
	Local     string        `json:"local"`
	Label     string        `json:"label,omitempty"`
	State     string        `json:"state"`
	ExpiresAt time.Time     `json:"expires_at"`
	Verify    *VerifyResult `json:"verify,omitempty"`
}

// VerifyResult records the optional reachability check. Status is zero when
// the HTTP request itself failed; any received status counts as reachable.
type VerifyResult struct {
	Checked bool `json:"checked"`
	Status  int  `json:"status"`
}

// Provisioner owns the leases created for one WispConfig.
type Provisioner interface {
	Provision(ctx context.Context, req Request) (Lease, error)
	Release(ctx context.Context, handle string) (Lease, bool)
	List() []Lease
}

// ServiceFactory constructs the service that publishes addr. name is the
// lease name ("lease-<handle>") and is used for both the service and its
// chain so concurrent leases never collide in gost's registries. addr is the
// resolved, allow-list-checked literal address, never the caller's hostname:
// the remote-forward handler would otherwise re-resolve a hostname per
// connection for the whole lease lifetime.
//
// Production uses the real gost rtcp service; tests inject a fake.
type ServiceFactory func(ctx context.Context, name, addr string) (service.Service, error)

// lease is the mutable record behind a Lease. Fields are guarded by the
// provisioner mutex; done is set once at construction.
type lease struct {
	Lease

	svc     service.Service
	host    string
	timer   *time.Timer
	done    chan struct{}
	stopped bool
	closed  bool
}

type provisioner struct {
	cfg     config.WispConfig
	allow   []netip.Prefix
	factory ServiceFactory

	mu       sync.Mutex
	leases   map[string]*lease
	expired  []*lease // FIFO order of expiry, capped at maxExpiredRecords
	reserved int      // slots held by in-flight Provision calls
}

// New returns a provisioner for cfg. A nil factory uses the real gost relay
// wiring; tests pass a fake.
//
// Zero config values fall back to the package defaults, so New never produces
// unusable URLs or unbounded leases.
func New(cfg config.WispConfig, factory ServiceFactory) Provisioner {
	if cfg.Domain == "" {
		cfg.Domain = config.DefaultWispDomain
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = config.DefaultWispMaxTTL
	}
	if cfg.MaxLeases <= 0 {
		cfg.MaxLeases = config.DefaultWispMaxLeases
	}
	if factory == nil {
		factory = realServiceFactory(cfg)
	}
	return &provisioner{
		cfg:     cfg,
		allow:   parseAllow(cfg.Allow),
		factory: factory,
		leases:  make(map[string]*lease),
	}
}

// Provision publishes req.Local and waits for the relay to assign the public
// label. The returned lease is active; its TTL timer and re-bind watcher are
// already running.
func (p *provisioner) Provision(ctx context.Context, req Request) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	target, err := p.checkTarget(ctx, req.Local)
	if err != nil {
		return Lease{}, err
	}

	ttl := p.leaseTTL(req.TTL)
	handle, err := newHandle()
	if err != nil {
		return Lease{}, err
	}
	name := "lease-" + handle

	if err := p.reserve(); err != nil {
		return Lease{}, err
	}
	reserved := true
	unreserve := func() {
		if reserved {
			reserved = false
			p.unreserve()
		}
	}

	svc, err := p.factory(ctx, name, target)
	if err != nil {
		unreserve()
		return Lease{}, fmt.Errorf("wisp: build service: %w", err)
	}
	if svc == nil {
		unreserve()
		return Lease{}, errors.New("wisp: factory returned a nil service")
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- svc.Serve() }()

	fail := func(err error) (Lease, error) {
		svc.Close()
		releaseReal(svc)
		unreserve()
		return Lease{}, err
	}

	host, err := p.waitForHost(ctx, svc, serveErr)
	if err != nil {
		return fail(err)
	}
	url := p.url(host)

	var verify *VerifyResult
	if req.Verify {
		verify = verifyURL(ctx, url)
	}

	l := &lease{
		Lease: Lease{
			Handle:    handle,
			URL:       url,
			Local:     req.Local,
			Label:     req.Label,
			State:     StateActive,
			ExpiresAt: time.Now().Add(ttl),
			Verify:    verify,
		},
		svc:  svc,
		host: host,
		done: make(chan struct{}),
	}

	// The timer callback blocks on p.mu, so even a zero-length TTL cannot
	// expire the lease before it is stored. Snapshot while still holding the
	// mutex so a TTL that fires immediately after the unlock cannot race the
	// caller's copy.
	p.mu.Lock()
	l.timer = time.AfterFunc(ttl, func() { p.expire(l) })
	p.leases[handle] = l
	p.reserved--
	out := l.snapshot()
	p.mu.Unlock()
	reserved = false

	go p.watch(l)

	return out, nil
}

// Release stops the service and forgets the lease. A second Release for the
// same handle reports false; it never closes the service twice. Once an
// expired record has been pruned by the maxExpiredRecords cap, Release also
// reports false: the record and its (already closed) service are gone.
func (p *provisioner) Release(ctx context.Context, handle string) (Lease, bool) {
	if handle == "" {
		return Lease{}, false
	}

	p.mu.Lock()
	l, ok := p.leases[handle]
	if !ok {
		p.mu.Unlock()
		return Lease{}, false
	}
	delete(p.leases, handle)
	p.dropExpiredLocked(l)
	l.stopLocked()
	alreadyClosed := l.closed
	l.closed = true
	out := l.snapshot()
	svc := l.svc
	l.svc = nil
	p.mu.Unlock()

	if !alreadyClosed && svc != nil {
		svc.Close()
		releaseReal(svc)
	}
	return out, true
}

// List returns a snapshot of every lease, including expired ones, ordered by
// expiry. Expired leases remain until they are released or pruned by the
// maxExpiredRecords cap.
func (p *provisioner) List() []Lease {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]Lease, 0, len(p.leases))
	for _, l := range p.leases {
		out = append(out, l.snapshot())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExpiresAt.Equal(out[j].ExpiresAt) {
			return out[i].Handle < out[j].Handle
		}
		return out[i].ExpiresAt.Before(out[j].ExpiresAt)
	})
	return out
}

// checkTarget validates local, resolves it, and returns a pinned literal
// host:port. Every resolved address must be inside the allow list; the first
// address is then chosen as the pinned target. Pinning is deliberate: gost's
// remote-forward handler re-resolves a hostname for every connection over the
// whole lease lifetime, so passing the hostname through would allow a name
// that passed this check to later resolve to a denied or internal address.
//
// The check is all-or-nothing: a host that resolves to one allowed and one
// denied address is denied rather than silently using the allowed one. If a
// host resolves to several allowed addresses, the first is used.
func (p *provisioner) checkTarget(ctx context.Context, local string) (string, error) {
	host, port, err := net.SplitHostPort(local)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %v", ErrInvalidTarget, local, err)
	}
	if !validHost(host) {
		return "", fmt.Errorf("%w: %q: host must be an IP address or a DNS name", ErrInvalidTarget, local)
	}
	if !validPort(port) {
		return "", fmt.Errorf("%w: %q: port must be an integer in 1..65535", ErrInvalidTarget, local)
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("wisp: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("wisp: %q: %w", local, ErrTargetNotAllowed)
	}
	for _, addr := range addrs {
		if !p.allowed(addr.IP) {
			return "", fmt.Errorf("wisp: %q: %w", local, ErrTargetNotAllowed)
		}
	}

	picked, ok := netip.AddrFromSlice(addrs[0].IP)
	if !ok {
		return "", fmt.Errorf("wisp: %q: %w", local, ErrTargetNotAllowed)
	}
	return net.JoinHostPort(picked.Unmap().String(), port), nil
}

// validHost accepts an IP literal (v4 or v6) or a DNS name made only of
// [A-Za-z0-9._-]. Rejecting every other byte keeps shell metacharacters,
// URI delimiters ("?", "#", "/", "@"), and whitespace out of the gost URI
// that the factory builds.
func validHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// validPort accepts only ASCII digits in 1..65535, so a non-numeric or
// out-of-range port can never reach gost's address parser.
func validPort(port string) bool {
	if port == "" || len(port) > 5 {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

func (p *provisioner) allowed(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range p.allow {
		if prefix.Addr().Is4() != addr.Is4() {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// reserve claims one of the MaxLeases slots. Expired leases no longer occupy a
// slot: their tunnel is closed and only the record remains for reporting.
func (p *provisioner) reserve() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	used := p.reserved
	for _, l := range p.leases {
		if l.State != StateExpired {
			used++
		}
	}
	if used >= p.cfg.MaxLeases {
		return fmt.Errorf("wisp: max leases reached (%d)", p.cfg.MaxLeases)
	}
	p.reserved++
	return nil
}

func (p *provisioner) unreserve() {
	p.mu.Lock()
	p.reserved--
	p.mu.Unlock()
}

// waitForHost polls the listener until the relay negotiates a concrete host.
// A wildcard or empty address means the bind has not completed yet.
func (p *provisioner) waitForHost(ctx context.Context, svc service.Service, serveErr <-chan error) (string, error) {
	deadline := time.Now().Add(bindTimeout)
	for {
		if host := addrHost(svc.Addr()); host != "" {
			return host, nil
		}
		if !time.Now().Before(deadline) {
			return "", fmt.Errorf("wisp: tunnel did not publish an address within %v", bindTimeout)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case err := <-serveErr:
			if err != nil {
				return "", fmt.Errorf("wisp: service stopped: %w", err)
			}
			return "", errors.New("wisp: service stopped before publishing an address")
		case <-time.After(bindPollInterval):
		}
	}
}

// watch follows the listener address for the life of the lease and updates the
// public URL when the relay re-binds the tunnel. Reading the service and its
// address under the mutex guarantees expire/release have not cleared svc.
func (p *provisioner) watch(l *lease) {
	ticker := time.NewTicker(rebindInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
			p.mu.Lock()
			if l.stopped || l.svc == nil {
				p.mu.Unlock()
				return
			}
			host := addrHost(l.svc.Addr())
			if host == "" {
				p.mu.Unlock()
				continue
			}
			if host != l.host {
				l.host = host
				l.URL = p.url(host)
				l.State = StateRebound
			}
			p.mu.Unlock()
		}
	}
}

// expire closes an expired lease's tunnel, marks it expired, and drops its
// reference to the service. The record is kept (up to maxExpiredRecords) so
// List can report the expiry; Release removes it.
func (p *provisioner) expire(l *lease) {
	p.mu.Lock()
	cur, ok := p.leases[l.Handle]
	if !ok || cur != l || l.stopped {
		p.mu.Unlock()
		return
	}
	l.State = StateExpired
	l.stopLocked()
	l.closed = true
	svc := l.svc
	l.svc = nil
	p.expired = append(p.expired, l)
	p.trimExpiredLocked()
	p.mu.Unlock()

	if svc != nil {
		svc.Close()
		releaseReal(svc)
	}
}

// trimExpiredLocked enforces the expired-record cap in FIFO order. Pruned
// records are removed from the map as well, so List and Release both treat
// them as gone. The caller holds p.mu.
func (p *provisioner) trimExpiredLocked() {
	for len(p.expired) > maxExpiredRecords {
		old := p.expired[0]
		p.expired = p.expired[1:]
		if cur, ok := p.leases[old.Handle]; ok && cur == old {
			delete(p.leases, old.Handle)
		}
	}
}

// dropExpiredLocked removes l from the expired FIFO when it is released. The
// caller holds p.mu.
func (p *provisioner) dropExpiredLocked(l *lease) {
	if l.State != StateExpired {
		return
	}
	for i, old := range p.expired {
		if old == l {
			p.expired = append(p.expired[:i], p.expired[i+1:]...)
			return
		}
	}
}

// stopLocked stops the timer and watcher. The caller holds p.mu.
func (l *lease) stopLocked() {
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	if !l.stopped {
		close(l.done)
		l.stopped = true
	}
}

// snapshot returns a copy safe to hand to callers. The caller holds p.mu.
func (l *lease) snapshot() Lease {
	out := l.Lease
	if l.Verify != nil {
		v := *l.Verify
		out.Verify = &v
	}
	return out
}

func (p *provisioner) leaseTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = defaultLeaseTTL
	}
	if ttl > p.cfg.MaxTTL {
		ttl = p.cfg.MaxTTL
	}
	return ttl
}

func (p *provisioner) url(host string) string {
	return "https://" + host + "." + p.cfg.Domain
}

// verifyURL performs one GET. Any HTTP status means the public endpoint
// answered; only a transport error leaves Status zero.
func verifyURL(ctx context.Context, url string) *VerifyResult {
	res := &VerifyResult{Checked: true}

	reqCtx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return res
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	res.Status = resp.StatusCode
	return res
}

// addrHost returns the non-wildcard host of a listener address. An empty
// result means the bind has not produced a usable public label yet.
func addrHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if tcp.IP == nil || tcp.IP.IsUnspecified() {
			return ""
		}
		return tcp.IP.String()
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "0.0.0.0", "::":
		return ""
	}
	return host
}

// parseAllow converts the configured hosts and CIDRs into prefixes. An empty
// list means loopback-only. Invalid entries are ignored: validation rejects
// them at load time, and ignoring them here fails closed.
func parseAllow(entries []string) []netip.Prefix {
	if len(entries) == 0 {
		entries = config.DefaultWispAllow
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return prefixes
}

// newHandle returns an opaque lease identifier. Handles also name the per-lease
// chain in the registry, so they must be unique within the process.
func newHandle() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("wisp: handle: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
