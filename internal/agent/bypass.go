package agent

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

// Exit-node bypass, for backends such as macOS that route the exit node
// with plain routes and so must be told which hosts stay off the tunnel.
// On Linux the fwmark does this and the backend is no Bypasser.

const (
	resolveTTL     = 5 * time.Minute
	resolveFailTTL = 30 * time.Second
)

type resolved struct {
	addrs []netip.Addr
	at    time.Time
}

type resolver struct {
	mu     sync.Mutex
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	cache  map[string]resolved
}

// addrs returns the addresses of host, a literal IP or a name, caching
// lookups so a reconcile every few seconds stays cheap.
func (r *resolver) addrs(host string) []netip.Addr {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}
	}
	if host == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.cache[host]; ok {
		ttl := resolveTTL
		if len(c.addrs) == 0 {
			ttl = resolveFailTTL
		}
		if time.Since(c.at) < ttl {
			return c.addrs
		}
	}
	lookup := r.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	addrs, _ := lookup(ctx, host)
	cancel()
	if r.cache == nil {
		r.cache = map[string]resolved{}
	}
	r.cache[host] = resolved{addrs: addrs, at: time.Now()}
	return addrs
}

// setBypass tells a Bypasser backend the coordinator's address and every
// endpoint the peers and the relay may be reached at.
func (a *Agent) setBypass(name string, nm *mesh.NetMap, peers []wgctl.Peer) error {
	bp, ok := a.o.Backend.(wgctl.Bypasser)
	if !ok {
		return nil
	}
	a.mu.Lock()
	var hosts []string
	if u, err := url.Parse(a.st.URL); err == nil {
		hosts = append(hosts, u.Hostname())
	}
	a.mu.Unlock()
	eps := []string{}
	if nm.Relay != nil {
		eps = append(eps, nm.Relay.Endpoint)
	}
	for _, n := range nm.Peers {
		eps = append(eps, n.Endpoints...)
	}
	for _, p := range peers {
		eps = append(eps, p.Endpoint) // includes where WireGuard roamed to
	}
	for _, ep := range eps {
		if h, _, err := net.SplitHostPort(ep); err == nil {
			hosts = append(hosts, h)
		}
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, h := range hosts {
		for _, ip := range a.res.addrs(h) {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return bp.SetBypass(name, out)
}

// forwardNote says why this device's shared routes and exit node are not
// offered, or "" when they are or none are wanted. Called with mu held.
func (a *Agent) forwardNoteLocked() string {
	if a.noForward == nil || (len(a.st.Routes) == 0 && !a.st.Exit) {
		return ""
	}
	return "shared routes and exit node not offered: " + a.noForward.Error()
}
