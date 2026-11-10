package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/overspend1/wgh/internal/keys"
	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

// Timing of the path logic.
const (
	// DirectWindow: a handshake this recent means the direct path works.
	// WireGuard renews sessions every two minutes and drops them after three.
	DirectWindow = 180 * time.Second
	// TryEach is how long one candidate endpoint is tried before the next.
	TryEach   = 20 * time.Second
	Keepalive = 25
)

// JoinOptions configures 'wgh join'.
type JoinOptions struct {
	Token      string
	Name       string
	Interface  string
	ListenPort int
	Routes     []string
	Exit       bool
	ExitNode   string
	Version    string
	HTTP       func(c *Client) // test hook to replace the transport
}

// Join registers this device with a coordinator and saves its state. A new
// key pair is made here; only the public half is sent.
func Join(ctx context.Context, statePath string, o JoinOptions) (*State, error) {
	if _, err := os.Stat(statePath); err == nil {
		return nil, fmt.Errorf("%s already exists: this device is already in a mesh (run 'wgh leave' first)", statePath)
	}
	t, err := mesh.ParseToken(o.Token)
	if err != nil {
		return nil, err
	}
	if err := mesh.ValidRoutes(o.Routes); err != nil {
		return nil, err
	}
	if o.Name == "" {
		h, _ := os.Hostname()
		o.Name = mesh.CleanName(h)
	}
	if err := mesh.ValidName(o.Name); err != nil {
		return nil, err
	}
	kp, err := keys.NewPair()
	if err != nil {
		return nil, err
	}
	c := NewClient(t.URL, t.Pin, "")
	if o.HTTP != nil {
		o.HTTP(c)
	}
	resp, err := c.Join(ctx, mesh.JoinRequest{Token: o.Token, Name: o.Name, PublicKey: kp.Public, OS: runtime.GOOS, Version: o.Version})
	if err != nil {
		return nil, fmt.Errorf("join: %w", err)
	}
	st := &State{URL: t.URL, Pin: t.Pin, ID: resp.ID, Name: resp.Name, APIKey: resp.APIKey,
		PrivateKey: kp.Private, PublicKey: kp.Public, Address: resp.Address, Subnet: resp.Subnet,
		Interface: o.Interface, ListenPort: o.ListenPort, Routes: o.Routes, Exit: o.Exit, ExitNode: o.ExitNode}
	if st.Interface == "" {
		st.Interface = DefaultInterface
	}
	if st.ListenPort == 0 {
		st.ListenPort = DefaultPort
	}
	if err := Save(statePath, st); err != nil {
		return nil, fmt.Errorf("joined as %s but could not save the state (the coordinator still lists it; remove it there): %w", resp.Name, err)
	}
	return st, nil
}

// Leave tells the coordinator to forget this device and deletes its state.
func Leave(ctx context.Context, statePath string, hook func(*Client)) error {
	st, err := Load(statePath)
	if err != nil {
		return err
	}
	c := NewClient(st.URL, st.Pin, st.APIKey)
	if hook != nil {
		hook(c)
	}
	if err := c.Leave(ctx); err != nil && !errors.Is(err, ErrRemoved) {
		return fmt.Errorf("leave: %w (the state file was kept)", err)
	}
	return os.Remove(statePath)
}

// Options configures a running agent.
type Options struct {
	StatePath string
	Backend   wgctl.Backend
	HostsPath string // empty: don't touch a hosts file
	Version   string
	DryRun    bool
	Logf      func(format string, a ...any)
	Now       func() time.Time
	// DNS serves device names on the mesh address, port 53, and points
	// systemd-resolved at it for the mesh domain. The hosts file is still
	// written, so names work either way.
	DNS    bool
	DNSRun wgctl.Runner // runs resolvectl; nil means wgctl.ExecRunner
	// Test hooks.
	HTTP       func(c *Client)
	PollWait   time.Duration
	Heartbeat  time.Duration
	Tick       time.Duration
	LocalAddrs func() []netip.Addr
	NoSocket   bool

	// DNS test hooks.
	DNSAddr      netip.AddrPort          // listen here instead of <mesh address>:53
	DNSAvailable func(wgctl.Runner) bool // nil means meshdns.Available
}

type path struct {
	candidates []string
	idx        int
	since      time.Time
	direct     bool
	endpoint   string
	stat       wgctl.PeerStat
}

// Agent keeps one device in sync with the mesh.
type Agent struct {
	o      Options
	client *Client

	mu        sync.Mutex
	st        State
	nm        *mesh.NetMap
	paths     map[string]*path // by public key
	connected bool
	lastErr   string
	exitNote  string
	exitOn    bool
	applied   []wgctl.Peer
	upDone    bool
	upKey     string
	wake      chan struct{}
	stop      context.CancelFunc
	dnsOn     bool

	dnsMu sync.Mutex
	dns   dnsState
}

// New loads the device state and prepares an agent.
func New(o Options) (*Agent, error) {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.PollWait == 0 {
		o.PollWait = 25 * time.Second
	}
	if o.Heartbeat == 0 {
		o.Heartbeat = 20 * time.Second
	}
	if o.Tick == 0 {
		o.Tick = 5 * time.Second
	}
	if o.LocalAddrs == nil {
		o.LocalAddrs = localAddrs
	}
	if o.Backend == nil {
		return nil, errors.New("no WireGuard backend")
	}
	st, err := Load(o.StatePath)
	if err != nil {
		return nil, err
	}
	a := &Agent{o: o, st: *st, paths: map[string]*path{}, wake: make(chan struct{}, 1)}
	a.client = NewClient(st.URL, st.Pin, st.APIKey)
	if o.HTTP != nil {
		o.HTTP(a.client)
	}
	return a, nil
}

func (a *Agent) poke() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *Agent) iface() wgctl.Interface {
	addr := netip.MustParseAddr(a.st.Address)
	bits := 16
	if p, err := netip.ParsePrefix(a.st.Subnet); err == nil {
		bits = p.Bits()
	}
	return wgctl.Interface{Name: a.st.Interface, Address: netip.PrefixFrom(addr, bits),
		ListenPort: a.st.ListenPort, PrivateKey: a.st.PrivateKey}
}

// Run brings the interface up and keeps it in sync until ctx ends or the
// device is removed. It always takes the interface down before returning.
func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.mu.Lock()
	a.stop = cancel
	a.mu.Unlock()

	if err := a.o.Backend.Up(a.iface()); err != nil {
		return fmt.Errorf("bring up %s: %w", a.st.Interface, err)
	}
	a.mu.Lock()
	a.upDone, a.upKey = true, a.st.PrivateKey
	a.mu.Unlock()
	defer a.teardown()
	if err := a.reconcile(); err != nil {
		a.o.Logf("configure: %v", err)
	}

	if !a.o.NoSocket {
		closeSock, err := a.serveSocket(SocketPath(a.o.StatePath))
		if err != nil {
			a.o.Logf("status socket: %v (wgh status and the TUI won't see this agent)", err)
		} else {
			defer closeSock()
		}
	}

	errc := make(chan error, 2)
	go func() { errc <- a.pollLoop(ctx) }()
	go func() { errc <- a.heartbeatLoop(ctx) }()

	tick := time.NewTicker(a.o.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			if errors.Is(err, ErrRemoved) {
				a.o.Logf("removed from the mesh by the coordinator; taking %s down", a.st.Interface)
				return ErrRemoved
			}
			if err != nil && ctx.Err() == nil {
				return err
			}
		case <-tick.C:
		case <-a.wake:
		}
		if err := a.reconcile(); err != nil {
			a.o.Logf("configure: %v", err)
		}
	}
}

func (a *Agent) teardown() {
	a.stopDNS()
	if a.o.HostsPath != "" {
		if err := WriteHosts(a.o.HostsPath, nil, ""); err != nil {
			a.o.Logf("hosts file: %v", err)
		}
	}
	if err := a.o.Backend.Down(a.st.Interface); err != nil {
		a.o.Logf("take %s down: %v", a.st.Interface, err)
	}
}

func (a *Agent) setConn(ok bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connected = ok
	if err != nil {
		a.lastErr = err.Error()
	} else {
		a.lastErr = ""
	}
}

func (a *Agent) pollLoop(ctx context.Context) error {
	var since uint64
	backoff := time.Second
	for ctx.Err() == nil {
		pctx, cancel := context.WithTimeout(ctx, a.o.PollWait+15*time.Second)
		nm, err := a.client.NetMap(pctx, since, a.o.PollWait)
		cancel()
		if errors.Is(err, ErrRemoved) {
			return err
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			a.setConn(false, err)
			a.o.Logf("coordinator: %v (retrying)", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		a.setConn(true, nil)
		if nm.Version != since {
			since = nm.Version
			a.mu.Lock()
			a.nm = &nm
			a.mu.Unlock()
			a.poke()
		}
	}
	return nil
}

func (a *Agent) heartbeatLoop(ctx context.Context) error {
	t := time.NewTicker(a.o.Heartbeat)
	defer t.Stop()
	for {
		if err := a.heartbeat(ctx, ""); errors.Is(err, ErrRemoved) {
			return err
		} else if err != nil && ctx.Err() == nil {
			a.setConn(false, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (a *Agent) heartbeat(ctx context.Context, newPub string) error {
	a.mu.Lock()
	req := mesh.UpdateRequest{ListenPort: a.st.ListenPort, Routes: a.st.Routes, Exit: a.st.Exit,
		PublicKey: newPub, OS: runtime.GOOS, Version: a.o.Version}
	for _, p := range a.paths {
		req.RxBytes += p.stat.RxBytes
		req.TxBytes += p.stat.TxBytes
	}
	subnet, _ := netip.ParsePrefix(a.st.Subnet)
	port := a.st.ListenPort
	a.mu.Unlock()
	for _, ip := range a.o.LocalAddrs() {
		if !subnet.Contains(ip) {
			req.Endpoints = append(req.Endpoints, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		}
	}
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return a.client.Update(hctx, req)
}

// Rotate makes a new key pair, tells the coordinator, then switches to it.
func (a *Agent) Rotate(ctx context.Context) error {
	kp, err := keys.NewPair()
	if err != nil {
		return err
	}
	if err := a.heartbeat(ctx, kp.Public); err != nil {
		return fmt.Errorf("rotate key: %w", err)
	}
	a.mu.Lock()
	a.st.PrivateKey, a.st.PublicKey = kp.Private, kp.Public
	st := a.st
	a.applied = nil
	a.mu.Unlock()
	if err := Save(a.o.StatePath, &st); err != nil {
		return fmt.Errorf("new key is live but could not be saved: %w", err)
	}
	a.o.Logf("rotated WireGuard key")
	a.poke()
	return nil
}

// SetExitNode picks the exit node by name; "" turns it off.
func (a *Agent) SetExitNode(name string) error {
	a.mu.Lock()
	if name != "" && a.nm != nil {
		ok := a.nm.Relay != nil && a.nm.Relay.Name == name && a.nm.Relay.Exit
		for _, p := range a.nm.Peers {
			if p.Name == name && p.Exit {
				ok = true
			}
		}
		if !ok {
			a.mu.Unlock()
			return fmt.Errorf("%q is not an approved exit node", name)
		}
	}
	a.st.ExitNode = name
	st := a.st
	a.mu.Unlock()
	a.poke()
	return Save(a.o.StatePath, &st)
}

// Stop ends Run.
func (a *Agent) Stop() {
	a.mu.Lock()
	stop := a.stop
	a.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// reconcile reads the interface, updates each peer's path and applies any
// change. It is cheap when nothing changed.
func (a *Agent) reconcile() error {
	stats, err := a.o.Backend.Stats(a.st.Interface)
	if err != nil {
		stats = nil
	}
	byKey := map[string]wgctl.PeerStat{}
	for _, s := range stats {
		byKey[s.PublicKey] = s
	}
	now := a.o.Now()

	a.mu.Lock()
	ifc := a.iface()
	rekey := a.upKey != a.st.PrivateKey
	nm := a.nm
	if nm == nil {
		a.mu.Unlock()
		return nil
	}
	peers, routes, exitOn, forward, hosts := a.planLocked(nm, byKey, now)
	same := a.applied != nil && wgctl.EqualPeers(peers, a.applied) && !rekey
	a.mu.Unlock()

	var errs []error
	if rekey {
		if err := a.o.Backend.Up(ifc); err != nil {
			errs = append(errs, err)
		}
	}
	if !same {
		if err := a.o.Backend.SetPeers(ifc, peers); err != nil {
			errs = append(errs, err)
		} else {
			a.mu.Lock()
			a.applied, a.upKey = peers, ifc.PrivateKey
			if a.applied == nil {
				a.applied = []wgctl.Peer{}
			}
			a.mu.Unlock()
		}
	}
	errs = append(errs, a.o.Backend.SetRoutes(ifc.Name, routes))
	errs = append(errs, a.o.Backend.SetForward(ifc.Name, nm.Subnet, forward))
	if err := a.o.Backend.SetExit(ifc.Name, exitOn); err != nil {
		errs = append(errs, err)
		exitOn = false
	}
	a.mu.Lock()
	a.exitOn = exitOn
	a.mu.Unlock()
	if a.o.HostsPath != "" {
		errs = append(errs, WriteHosts(a.o.HostsPath, hosts, nm.Domain))
	}
	a.syncDNS(nm.Domain, hosts)
	return errors.Join(errs...)
}

// planLocked works out the desired WireGuard peers and routes.
func (a *Agent) planLocked(nm *mesh.NetMap, stats map[string]wgctl.PeerStat, now time.Time) (
	peers []wgctl.Peer, routes []string, exitOn, forward bool, hosts []HostEntry) {

	hosts = append(hosts, HostEntry{Address: nm.Self.Address, Name: nm.Self.Name})
	relayAllowed := []string{nm.Subnet}
	exitName := a.st.ExitNode
	a.exitNote = ""
	exitFound := exitName == ""
	seen := map[string]bool{}

	for _, n := range nm.Peers {
		hosts = append(hosts, HostEntry{Address: n.Address, Name: n.Name})
		var peerRoutes []string
		if !a.st.NoRoutes {
			for _, r := range n.Routes {
				if !slices.Contains(a.st.Routes, r) {
					peerRoutes = append(peerRoutes, r)
				}
			}
			routes = append(routes, peerRoutes...)
		}
		wantExit := exitName != "" && n.Name == exitName
		if wantExit {
			exitFound = true
			if !n.Exit {
				a.exitNote = exitName + " is not an approved exit node"
				wantExit = false
			}
		}
		if n.Static || n.PublicKey == "" {
			// Reached through the relay's subnet route; nothing to configure.
			if wantExit {
				a.exitNote = exitName + " can't be an exit node"
			}
			continue
		}
		seen[n.PublicKey] = true
		p := a.paths[n.PublicKey]
		if p == nil {
			p = &path{since: now}
			a.paths[n.PublicKey] = p
		}
		if !slices.Equal(p.candidates, n.Endpoints) {
			if !slices.Contains(n.Endpoints, p.endpoint) {
				p.idx, p.since = 0, now
			}
			p.candidates = n.Endpoints
		}
		st := stats[n.PublicKey]
		p.stat = st
		p.direct = !st.LastHandshake.IsZero() && now.Sub(st.LastHandshake) < DirectWindow
		if nm.Relay == nil {
			p.direct = true // nothing to fall back to: always route directly
		}
		switch {
		case p.direct && st.Endpoint != "":
			p.endpoint = st.Endpoint // WireGuard roams to where the peer really is
		case len(p.candidates) == 0:
			p.endpoint = ""
		default:
			if p.idx >= len(p.candidates) {
				p.idx = 0
			}
			if now.Sub(p.since) >= TryEach && !p.direct {
				p.idx, p.since = (p.idx+1)%len(p.candidates), now
			}
			p.endpoint = p.candidates[p.idx]
		}
		wp := wgctl.Peer{PublicKey: n.PublicKey, Endpoint: p.endpoint, Keepalive: Keepalive}
		if p.direct {
			wp.AllowedIPs = append([]string{n.Address + "/32"}, peerRoutes...)
			if wantExit {
				wp.AllowedIPs = append(wp.AllowedIPs, "0.0.0.0/0")
				exitOn = true
			}
		} else {
			relayAllowed = append(relayAllowed, peerRoutes...)
			if wantExit {
				a.exitNote = "waiting for a direct path to " + exitName + "; internet traffic stays local until then"
			}
		}
		peers = append(peers, wp)
	}
	for k := range a.paths {
		if !seen[k] {
			delete(a.paths, k)
		}
	}
	if nm.Relay != nil {
		hosts = append(hosts, HostEntry{Address: nm.Relay.Address, Name: nm.Relay.Name})
		if exitName == nm.Relay.Name {
			exitFound = true
			if nm.Relay.Exit {
				relayAllowed = append(relayAllowed, "0.0.0.0/0")
				exitOn = true
			} else {
				a.exitNote = "the relay is not an exit node (start wgh serve with --exit)"
			}
		}
		peers = append(peers, wgctl.Peer{PublicKey: nm.Relay.PublicKey, Endpoint: nm.Relay.Endpoint,
			AllowedIPs: dedupe(relayAllowed), Keepalive: Keepalive})
	}
	if !exitFound {
		a.exitNote = "no device called " + exitName
	}
	sort.Strings(routes)
	routes = dedupe(routes)
	forward = len(a.st.Routes) > 0 || a.st.Exit
	return peers, routes, exitOn, forward, hosts
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// localAddrs lists this machine's IPv4 addresses that another device on the
// same network might reach.
func localAddrs() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			pfx, err := netip.ParsePrefix(ad.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr()
			if ip.Is4() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
				out = append(out, ip)
			}
		}
	}
	return out
}
