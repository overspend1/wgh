package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/overspend1/wgh/internal/wgctl"
)

func srcs(rules []wgctl.FilterRule) string {
	var out []string
	for _, r := range rules {
		out = append(out, r.Src)
	}
	return strings.Join(out, " ")
}

// meshPeers names the devices d sees, without the relay.
func meshPeers(d *dev) string {
	var out []string
	for _, p := range d.a.Status().Peers {
		if !p.Relay {
			out = append(out, p.Name)
		}
	}
	return strings.Join(out, " ")
}

// TestACLEndToEnd runs agents against a coordinator with an access policy
// and checks each device's own inbound filter, what it sees, and the exit
// node rule; then removes the policy and checks every filter goes away.
func TestACLEndToEnd(t *testing.T) {
	r := newRig(t)
	policy := filepath.Join(r.dir, "coord", "acl.json")
	if err := os.WriteFile(policy, []byte(`{"rules": [
		{"from": ["laptop"], "to": ["pve1"]},
		{"from": ["pve1"], "to": ["nas"]}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.sweep()
	laptop := r.join("laptop", "192.168.1.10", nil, false)
	pve1 := r.join("pve1", "192.168.1.20", []string{"192.168.50.0/24"}, true)
	nas := r.join("nas", "192.168.1.30", nil, false)
	if _, _, err := r.srv.Approve("pve1"); err != nil {
		t.Fatal(err)
	}
	// Every source is let in over IPv4 and over IPv6.
	relay := r.srv.Status().Relay.Address + "/32 " + r.srv.Status().Relay.Address6 + "/128"

	filter := func(d *dev, want string) {
		t.Helper()
		eventually(t, "filter "+want, func() bool {
			s := d.fake.Snapshot()
			return s.Filter && s.FilterScope == wgctl.FilterInbound && srcs(s.FilterRules) == want
		})
	}
	// Nobody may connect to laptop; laptop may connect to pve1 (and on to
	// its LAN, which the same filter covers); pve1 may connect to nas. The
	// relay is always let in. nas may not reach pve1, so it isn't given
	// pve1's LAN and doesn't take connections from it either.
	filter(laptop, relay)
	filter(pve1, relay+" 10.144.0.2/32 fd77:6768::a90:2/128")
	filter(nas, relay+" 10.144.0.3/32 fd77:6768::a90:3/128")

	// laptop and nas have no rule either way, so they don't see each other.
	eventually(t, "nas sees only pve1", func() bool { return meshPeers(nas) == "pve1" })
	if _, ok := laptop.fake.Snapshot().Peer(nas.pub); ok {
		t.Error("laptop has nas as a peer")
	}

	// laptop may use pve1's route and exit; nas, which pve1 reaches but
	// which may not reach pve1, gets neither.
	eventually(t, "laptop gets pve1's route", func() bool {
		return slices.Contains(laptop.fake.Snapshot().Routes, "192.168.50.0/24")
	})
	if err := laptop.a.SetExitNode("pve1"); err != nil {
		t.Fatalf("laptop exit via pve1: %v", err)
	}
	if err := nas.a.SetExitNode("pve1"); err == nil {
		t.Error("nas may use pve1 as exit node without being allowed to reach it")
	}
	if slices.Contains(nas.fake.Snapshot().Routes, "192.168.50.0/24") {
		t.Error("nas got pve1's route")
	}

	// Without the policy every filter is removed and everyone sees everyone.
	if err := os.Remove(policy); err != nil {
		t.Fatal(err)
	}
	r.sweep()
	for _, d := range []*dev{laptop, pve1, nas} {
		eventually(t, "filter removed", func() bool { return !d.fake.Snapshot().Filter })
	}
	eventually(t, "nas sees everyone", func() bool { return meshPeers(nas) == "laptop pve1" })
}
