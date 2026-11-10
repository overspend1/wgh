package agent

import (
	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

// inboundFilter is the device's own access filter: new connections coming
// in on the mesh interface, to this machine or on to the LAN routes and
// exit it shares, only from peers the policy lets connect, and from the
// relay. Replies always pass. nil (no filter) when the coordinator has no
// access policy, so a mesh without acl.json behaves exactly as before.
func inboundFilter(nm *mesh.NetMap) []wgctl.FilterRule {
	if !nm.ACL {
		return nil
	}
	rules := []wgctl.FilterRule{}
	// The backend keeps the IPv6 rules in an IPv6 filter of their own, so
	// the policy holds over IPv6 too.
	src6 := func(addr6 string) {
		if nm.Subnet6 != "" && addr6 != "" {
			rules = append(rules, wgctl.FilterRule{Src: addr6 + "/128"})
		}
	}
	if nm.Relay != nil && nm.Relay.Address != "" {
		rules = append(rules, wgctl.FilterRule{Src: nm.Relay.Address + "/32"})
		src6(nm.Relay.Address6)
	}
	for _, n := range nm.Peers {
		if !n.CanConnect || n.Address == "" {
			continue
		}
		rules = append(rules, wgctl.FilterRule{Src: n.Address + "/32"})
		src6(n.Address6)
		// Hosts on the LAN a peer shares count as that peer.
		for _, r := range n.Routes {
			rules = append(rules, wgctl.FilterRule{Src: r})
		}
	}
	return rules
}

// applyFilter installs the inbound filter when the backend can filter. A
// backend that can't (macOS) leaves enforcement to the relay and the peers.
func (a *Agent) applyFilter(name string, nm *mesh.NetMap) error {
	f, ok := a.o.Backend.(wgctl.Filter)
	if !ok {
		return nil
	}
	return f.SetFilter(name, wgctl.FilterInbound, inboundFilter(nm))
}
