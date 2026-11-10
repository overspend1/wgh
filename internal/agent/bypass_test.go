package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/overspend1/wgh/internal/wgctl"
)

// testLookup resolves the relay's test name without touching the network.
func testLookup(_ context.Context, host string) ([]netip.Addr, error) {
	if host == "relay.example" {
		return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
	}
	return nil, errors.New("no such host")
}

// noForward is a fake that, like macOS, can't forward for the mesh.
type noForward struct{ *wgctl.Fake }

func (noForward) CanForward() error { return wgctl.ErrNoForward }

func (n noForward) SetForward(name, subnet string, on bool) error {
	if on {
		return wgctl.ErrNoForward
	}
	return n.Fake.SetForward(name, subnet, on)
}

func TestExitBypassHosts(t *testing.T) {
	r := newRig(t)
	a := r.join("laptop", "192.168.1.10", nil, false)
	b := r.join("pve1", "192.168.1.20", nil, true)
	eventually(t, "direct path", func() bool { return peerStatus(a, "pve1").Path == PathDirect })
	if _, _, err := r.srv.Approve("pve1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "exit approved", func() bool { return peerStatus(a, "pve1").Exit })
	if got := a.fake.Snapshot().Bypass; got != nil {
		t.Fatalf("bypass set before any exit node: %v", got)
	}
	if err := a.a.SetExitNode("pve1"); err != nil {
		t.Fatal(err)
	}
	// The coordinator (127.0.0.1 here), the relay's endpoint by name, and
	// every endpoint pve1 may be reached at stay off the tunnel.
	want := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.168.1.20"),
		netip.MustParseAddr("203.0.113.1")}
	eventually(t, "bypass hosts", func() bool {
		s := a.fake.Snapshot()
		return s.Exit && slices.Equal(s.Bypass, want)
	})
	if got := b.fake.Snapshot().Bypass; got != nil {
		t.Errorf("pve1 uses no exit node but got bypass hosts %v", got)
	}
}

func TestNoForwardNotOffered(t *testing.T) {
	r := newRig(t)
	var mac *wgctl.Fake
	d := r.joinWith("mac", "192.168.1.30", []string{"192.168.60.0/24"}, true, func(f *wgctl.Fake) wgctl.Backend {
		mac = f
		return noForward{f}
	})
	other := r.join("laptop", "192.168.1.10", nil, false)
	eventually(t, "direct path", func() bool { return peerStatus(other, "mac").Path == PathDirect })
	time.Sleep(100 * time.Millisecond) // several heartbeats
	for _, n := range r.srv.Status().Devices {
		if n.Name == "mac" && (len(n.PendingRoutes) > 0 || n.PendingExit || len(n.Routes) > 0 || n.Exit) {
			t.Fatalf("mac offered what it can't forward: %+v", n)
		}
	}
	if mac.Snapshot().Forward {
		t.Error("forwarding turned on")
	}
	if st := d.a.Status(); !strings.Contains(st.ForwardNote, "need Linux") {
		t.Errorf("forward note = %q", st.ForwardNote)
	}
	if st := other.a.Status(); st.ForwardNote != "" {
		t.Errorf("laptop wants nothing forwarded but has note %q", st.ForwardNote)
	}
}
