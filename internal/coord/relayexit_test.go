package coord

import (
	"slices"
	"testing"

	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

func TestRelayedExitNode(t *testing.T) {
	r := newACLRig(t, "")
	r.join("pve1", nil, true)
	r.join("nas", nil, true)
	r.join("laptop", nil, false)
	r.join("desk", nil, false)
	ask := func(name, exit string) {
		t.Helper()
		if err := r.srv.Update(r.keys[name], mesh.UpdateRequest{ExitViaRelay: exit}, ""); err != nil {
			t.Fatal(err)
		}
	}

	ask("laptop", "pve1")
	if nm := r.netmap("laptop"); nm.RelayExit != "pve1" {
		t.Fatalf("laptop RelayExit = %q", nm.RelayExit)
	}
	if nm := r.netmap("desk"); nm.RelayExit != "" {
		t.Fatalf("desk asked for nothing but got %q", nm.RelayExit)
	}
	if err := r.srv.syncRelay(); err != nil {
		t.Fatal(err)
	}
	snap := r.relay.Snapshot()
	pubOf := func(name string) string {
		for _, d := range r.srv.Status().Devices {
			if d.Name == name {
				return d.PublicKey
			}
		}
		t.Fatalf("no %s", name)
		return ""
	}
	p, _ := snap.Peer(pubOf("pve1"))
	if !slices.Contains(p.AllowedIPs, "0.0.0.0/0") {
		t.Fatalf("pve1 on the relay: %v", p.AllowedIPs)
	}
	if !slices.Equal(snap.Sources, []string{addr(r, "laptop")}) {
		t.Fatalf("sources = %v", snap.Sources)
	}

	// One exit node at a time: two devices for nas outvote one for pve1.
	ask("desk", "nas")
	r.join("tv", nil, false)
	ask("tv", "nas")
	if nm := r.netmap("laptop"); nm.RelayExit != "" {
		t.Errorf("laptop should lose the relayed exit, got %q", nm.RelayExit)
	}
	if nm := r.netmap("tv"); nm.RelayExit != "nas" {
		t.Errorf("tv RelayExit = %q", nm.RelayExit)
	}
	r.srv.syncRelay()
	snap = r.relay.Snapshot()
	if p, _ := snap.Peer(pubOf("pve1")); slices.Contains(p.AllowedIPs, "0.0.0.0/0") {
		t.Error("pve1 still holds the default route")
	}
	if len(snap.Sources) != 2 {
		t.Errorf("sources = %v", snap.Sources)
	}

	// Nobody asks: everything is undone.
	ask("desk", "")
	ask("tv", "")
	ask("laptop", "")
	r.srv.syncRelay()
	if snap := r.relay.Snapshot(); len(snap.Sources) != 0 {
		t.Errorf("sources left: %v", snap.Sources)
	}
}

func TestRelayedExitRespectsACL(t *testing.T) {
	r := newACLRig(t, `{"rules":[{"from":["*"],"to":["*"]},{"from":["pve1"],"to":["laptop"]}]}`)
	r.join("pve1", nil, true)
	r.join("laptop", nil, false)
	r.srv.Update(r.keys["laptop"], mesh.UpdateRequest{ExitViaRelay: "pve1"}, "")
	if nm := r.netmap("laptop"); nm.RelayExit != "pve1" {
		t.Fatalf("allowed by '*': RelayExit = %q", nm.RelayExit)
	}
	rules := r.srv.RelayFilter()
	if !slices.Contains(rules, wgctl.FilterRule{Src: addr(r, "laptop")}) {
		t.Errorf("relay filter lacks laptop's internet rule: %v", rules)
	}

	r2 := newACLRig(t, `{"rules":[{"from":["pve1"],"to":["laptop"]}]}`)
	r2.join("pve1", nil, true)
	r2.join("laptop", nil, false)
	r2.srv.Update(r2.keys["laptop"], mesh.UpdateRequest{ExitViaRelay: "pve1"}, "")
	if nm := r2.netmap("laptop"); nm.RelayExit != "" {
		t.Errorf("laptop may not reach pve1 but got the relayed exit")
	}
}
