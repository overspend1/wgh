package wgctl

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Network simulates the paths between fake interfaces: which endpoints can
// reach each other. A handshake happens between two fake peers when each
// has the other configured and the endpoint one of them dials is reachable.
type Network struct {
	mu      sync.Mutex
	nodes   map[string]*Fake // by public key
	blocked map[string]bool  // "dialerPub>endpoint"
	Now     func() time.Time
}

// NewNetwork returns an empty simulated network.
func NewNetwork() *Network {
	return &Network{nodes: map[string]*Fake{}, blocked: map[string]bool{}, Now: time.Now}
}

// Block makes endpoint unreachable from the device with public key from.
func (n *Network) Block(from, endpoint string) {
	n.mu.Lock()
	n.blocked[from+">"+endpoint] = true
	n.mu.Unlock()
}

// Unblock undoes Block.
func (n *Network) Unblock(from, endpoint string) {
	n.mu.Lock()
	delete(n.blocked, from+">"+endpoint)
	n.mu.Unlock()
}

// Fake is an in-memory Backend. With Log set it prints what it would do,
// which is what 'wgh up --dry-run' shows.
type Fake struct {
	Log     io.Writer
	Net     *Network
	Addr    string // the endpoint other fakes reach this one at
	mu      sync.Mutex
	ifc     *Interface
	peers   []Peer
	routes  []string
	exit    bool
	forward bool
	bypass  []netip.Addr
	hs      map[string]time.Time

	filterOn    bool
	filterScope FilterScope
	filter      []FilterRule
	sources     []string
}

// NewFake returns a fake backend, optionally attached to a network.
func NewFake(log io.Writer, n *Network, addr string) *Fake {
	return &Fake{Log: log, Net: n, Addr: addr, hs: map[string]time.Time{}}
}

func (f *Fake) logf(format string, a ...any) {
	if f.Log != nil {
		fmt.Fprintf(f.Log, format+"\n", a...)
	}
}

// Up implements Backend.
func (f *Fake) Up(ifc Interface) error {
	f.mu.Lock()
	c := ifc
	f.ifc = &c
	f.mu.Unlock()
	f.logf("[dry-run] create %s with address %s, MTU %d", ifc.Name, ifc.Address, max(ifc.MTU, 1280))
	return nil
}

// SetPeers implements Backend.
func (f *Fake) SetPeers(ifc Interface, peers []Peer) error {
	f.mu.Lock()
	old := f.ifc
	c := ifc
	f.ifc = &c
	same := EqualPeers(f.peers, peers)
	f.peers = SortedPeers(peers)
	f.mu.Unlock()
	if f.Net != nil && ifc.PrivateKey != "" {
		f.Net.mu.Lock()
		if old != nil && old.PrivateKey != ifc.PrivateKey {
			for k, v := range f.Net.nodes {
				if v == f {
					delete(f.Net.nodes, k)
				}
			}
		}
		f.Net.nodes[pubOf(ifc.PrivateKey)] = f
		f.Net.mu.Unlock()
	}
	if same {
		return nil
	}
	f.logf("[dry-run] %s: %d peer(s), listen port %d", ifc.Name, len(peers), ifc.ListenPort)
	for _, p := range SortedPeers(peers) {
		ep := p.Endpoint
		if ep == "" {
			ep = "(none)"
		}
		allowed := strings.Join(p.AllowedIPs, ", ")
		if allowed == "" {
			allowed = "(none, relayed)"
		}
		f.logf("[dry-run]   peer %s… endpoint %s allowed %s", short(p.PublicKey), ep, allowed)
	}
	return nil
}

// pubOf is replaced in tests that attach fakes to a Network; it maps a
// private key to the public key the network knows the fake by.
var pubOf = func(priv string) string { return "pub:" + priv }

// SetPublicKeyFunc lets callers tell the fake network how to derive public
// keys (the real derivation lives in the keys package, which imports nothing
// from here).
func SetPublicKeyFunc(f func(priv string) string) { pubOf = f }

func short(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}

// Stats implements Backend. Attached to a Network, it simulates handshakes.
func (f *Fake) Stats(string) ([]PeerStat, error) {
	f.mu.Lock()
	peers := append([]Peer(nil), f.peers...)
	var me string
	if f.ifc != nil {
		me = pubOf(f.ifc.PrivateKey)
	}
	f.mu.Unlock()
	out := make([]PeerStat, 0, len(peers))
	for _, p := range peers {
		s := PeerStat{PublicKey: p.PublicKey, Endpoint: p.Endpoint}
		if f.Net != nil {
			now := f.Net.Now()
			if f.Net.reachable(me, p) || f.Net.reverse(me, p.PublicKey) {
				f.mu.Lock()
				f.hs[p.PublicKey] = now
				f.mu.Unlock()
			}
			f.mu.Lock()
			s.LastHandshake = f.hs[p.PublicKey]
			f.mu.Unlock()
			if !s.LastHandshake.IsZero() {
				s.RxBytes, s.TxBytes = 4096, 2048
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// reachable: me dials p at p.Endpoint and the fake there knows me.
func (n *Network) reachable(me string, p Peer) bool {
	if p.Endpoint == "" {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.blocked[me+">"+p.Endpoint] {
		return false
	}
	other := n.nodes[p.PublicKey]
	if other == nil || other.Addr != p.Endpoint {
		return false
	}
	return other.knows(me)
}

// reverse: the peer dials me successfully.
func (n *Network) reverse(me, peerPub string) bool {
	n.mu.Lock()
	other := n.nodes[peerPub]
	self := n.nodes[me]
	n.mu.Unlock()
	if other == nil || self == nil {
		return false
	}
	other.mu.Lock()
	var mine *Peer
	for i := range other.peers {
		if other.peers[i].PublicKey == me {
			p := other.peers[i]
			mine = &p
		}
	}
	other.mu.Unlock()
	if mine == nil || mine.Endpoint == "" {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return !n.blocked[peerPub+">"+mine.Endpoint] && self.Addr == mine.Endpoint && self.knows(peerPub)
}

func (f *Fake) knows(pub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.peers {
		if p.PublicKey == pub {
			return true
		}
	}
	return false
}

// SetRoutes implements Backend.
func (f *Fake) SetRoutes(name string, routes []string) error {
	r := append([]string(nil), routes...)
	sort.Strings(r)
	f.mu.Lock()
	same := strings.Join(r, ",") == strings.Join(f.routes, ",")
	f.routes = r
	f.mu.Unlock()
	if !same {
		if len(r) == 0 {
			f.logf("[dry-run] %s: no extra routes", name)
		} else {
			f.logf("[dry-run] %s: routes %s", name, strings.Join(r, ", "))
		}
	}
	return nil
}

// SetExit implements Backend.
func (f *Fake) SetExit(name string, on bool) error {
	f.mu.Lock()
	changed := f.exit != on
	f.exit = on
	f.mu.Unlock()
	if changed {
		f.logf("[dry-run] %s: send all internet traffic through the mesh: %v", name, on)
	}
	return nil
}

// SetForward implements Backend.
func (f *Fake) SetForward(name, subnet string, on bool) error {
	f.mu.Lock()
	changed := f.forward != on
	f.forward = on
	f.mu.Unlock()
	if changed {
		f.logf("[dry-run] %s: forward and NAT traffic from %s: %v", name, subnet, on)
	}
	return nil
}

// SetBypass implements Bypasser by recording the hosts.
func (f *Fake) SetBypass(_ string, hosts []netip.Addr) error {
	f.mu.Lock()
	f.bypass = append([]netip.Addr(nil), hosts...)
	f.mu.Unlock()
	return nil
}

// Down implements Backend.
func (f *Fake) Down(name string) error {
	f.mu.Lock()
	f.ifc, f.peers, f.routes, f.exit, f.forward, f.bypass = nil, nil, nil, false, false, nil
	f.filterOn, f.filter = false, nil
	f.mu.Unlock()
	f.logf("[dry-run] remove %s", name)
	return nil
}

// Snapshot is the fake's current configuration, for tests.
type Snapshot struct {
	Up      bool
	Address netip.Prefix
	Peers   []Peer
	Routes  []string
	Exit    bool
	Forward bool
	Bypass  []netip.Addr // last SetBypass
	// Filter is set when an access filter is on; FilterRules may be empty.
	Filter      bool
	FilterScope FilterScope
	FilterRules []FilterRule
	Sources     []string // last SetSourceRoutes
}

// Snapshot returns the current configuration.
func (f *Fake) Snapshot() Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := Snapshot{Up: f.ifc != nil, Peers: append([]Peer(nil), f.peers...),
		Routes: append([]string(nil), f.routes...), Exit: f.exit, Forward: f.forward,
		Bypass: append([]netip.Addr(nil), f.bypass...),
		Filter: f.filterOn, FilterScope: f.filterScope, FilterRules: append([]FilterRule(nil), f.filter...),
		Sources: append([]string(nil), f.sources...)}
	if f.ifc != nil {
		s.Address = f.ifc.Address
	}
	return s
}

// Peer returns the configured peer with public key pub, if any.
func (s Snapshot) Peer(pub string) (Peer, bool) {
	for _, p := range s.Peers {
		if p.PublicKey == pub {
			return p, true
		}
	}
	return Peer{}, false
}
