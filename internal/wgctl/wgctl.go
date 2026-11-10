// Package wgctl applies WireGuard settings to a real interface. The Linux
// backend runs ip, wg, iptables and sysctl and needs root. The Fake backend
// keeps everything in memory for tests and --dry-run.
package wgctl

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// FwMark marks WireGuard's own packets so they skip the exit-node route.
const FwMark = 0x5767 // "Wg"

// RouteTable holds the default route used when an exit node is on.
const RouteTable = 5767

// Interface describes the local WireGuard interface.
type Interface struct {
	Name       string
	Address    netip.Prefix // e.g. 10.144.0.5/16
	ListenPort int
	PrivateKey string
	MTU        int
}

// Peer is the desired state of one WireGuard peer.
type Peer struct {
	PublicKey  string
	Endpoint   string // host:port, may be empty
	AllowedIPs []string
	Keepalive  int
}

// PeerStat is what the interface reports about one peer.
type PeerStat struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Backend configures one WireGuard interface.
type Backend interface {
	// Up creates the interface if needed and sets its address and MTU.
	Up(ifc Interface) error
	// SetPeers replaces the peer list, keys and listen port in one step.
	SetPeers(ifc Interface, peers []Peer) error
	// Stats reads handshake and traffic counters.
	Stats(name string) ([]PeerStat, error)
	// SetRoutes makes the extra routes through the interface exactly routes.
	SetRoutes(name string, routes []string) error
	// SetExit sends all IPv4 traffic through the interface (on) or stops.
	SetExit(name string, on bool) error
	// SetForward lets this machine forward and NAT mesh traffic out to its
	// LAN and the internet, for exit nodes, subnet routers and the relay.
	SetForward(name, subnet string, on bool) error
	// Down removes the interface and everything set up for it.
	Down(name string) error
}

// SortedPeers returns peers ordered by public key with sorted AllowedIPs,
// so two peer lists can be compared.
func SortedPeers(in []Peer) []Peer {
	out := make([]Peer, len(in))
	for i, p := range in {
		p.AllowedIPs = append([]string(nil), p.AllowedIPs...)
		sort.Strings(p.AllowedIPs)
		out[i] = p
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out
}

// EqualPeers reports whether two peer lists configure the same thing.
func EqualPeers(a, b []Peer) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = SortedPeers(a), SortedPeers(b)
	for i := range a {
		if a[i].PublicKey != b[i].PublicKey || a[i].Endpoint != b[i].Endpoint ||
			a[i].Keepalive != b[i].Keepalive ||
			strings.Join(a[i].AllowedIPs, ",") != strings.Join(b[i].AllowedIPs, ",") {
			return false
		}
	}
	return true
}
