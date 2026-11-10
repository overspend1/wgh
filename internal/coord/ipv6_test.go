package coord

import (
	"slices"
	"strings"
	"testing"

	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

// newIPv6Rig is an allow-all rig whose relay is an exit node when exit is
// set, with fake as the relay backend.
func newIPv6Rig(t *testing.T, exit bool, fake *wgctl.Fake) *aclRig {
	t.Helper()
	r := &aclRig{t: t, relay: fake, keys: map[string]string{}}
	srv, err := New(Options{Dir: t.TempDir(), Endpoint: "relay.example", PlainHTTP: true, URL: "http://127.0.0.1:1",
		Exit: exit, Backend: fake, Logf: func(f string, a ...any) { r.logs = append(r.logs, f) }})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	return r
}

func TestNetMapIPv6(t *testing.T) {
	r := newACLRig(t, "")
	r.join("laptop", nil, false)
	r.join("pve1", []string{"192.168.50.0/24", "2001:db8:50::/48"}, true)
	nm := r.netmap("laptop")
	if nm.Subnet6 != "fd77:6768::/64" || nm.Self.Address6 != "fd77:6768::a90:2" || nm.Relay.Address6 != "fd77:6768::a90:1" {
		t.Fatalf("netmap: subnet6 %q self %q relay %q", nm.Subnet6, nm.Self.Address6, nm.Relay.Address6)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].Address6 != "fd77:6768::a90:3" || !slices.Contains(nm.Peers[0].Routes, "2001:db8:50::/48") {
		t.Fatalf("peers: %+v", nm.Peers)
	}
	if st := r.srv.Status(); st.Subnet6 != mesh.DefaultSubnet6 || st.Devices[0].Address6 != "fd77:6768::a90:2" {
		t.Errorf("admin status: %+v", st)
	}
	// IPv6 routes are checked like IPv4 ones.
	if err := r.srv.Update(r.keys["laptop"], mesh.UpdateRequest{Routes: []string{"::/0"}}, ""); err == nil {
		t.Error("::/0 accepted as a route")
	}
}

// TestRelayIPv6Config: the relay interface has its IPv6 address and each
// device's relay peer covers its /128 and its IPv6 routes.
func TestRelayIPv6Config(t *testing.T) {
	r := newACLRig(t, "")
	r.join("laptop", nil, false)
	r.join("pve1", []string{"192.168.50.0/24", "2001:db8:50::/48"}, false)
	if ifc := r.srv.relayInterface(); ifc.Address.String() != "10.144.0.1/16" || ifc.Address6.String() != "fd77:6768::a90:1/64" {
		t.Fatalf("relay interface %s %s", ifc.Address, ifc.Address6)
	}
	if err := r.srv.syncRelay(); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range r.relay.Snapshot().Peers {
		got[strings.Join(p.AllowedIPs, " ")] = p.PublicKey
	}
	for _, want := range []string{
		"10.144.0.2/32 fd77:6768::a90:2/128",
		"10.144.0.3/32 192.168.50.0/24 2001:db8:50::/48 fd77:6768::a90:3/128",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("no relay peer with %s; have %v", want, got)
		}
	}
}

// TestRelayForward6: the relay forwards and NATs IPv6 only as an exit node.
func TestRelayForward6(t *testing.T) {
	for _, exit := range []bool{false, true} {
		fake := wgctl.NewFake(nil, nil, "")
		r := newIPv6Rig(t, exit, fake)
		if err := fake.Up(r.srv.relayInterface()); err != nil {
			t.Fatal(err)
		}
		r.srv.startRelay6()
		if s := fake.Snapshot(); s.Forward6 != exit || s.Address6.String() != "fd77:6768::a90:1/64" {
			t.Errorf("exit %v: forward6 %v address6 %s", exit, s.Forward6, s.Address6)
		}
	}
	// A relay host without IPv6 says so and carries on.
	fake := wgctl.NewFake(nil, nil, "")
	fake.NoIPv6 = true
	r := newIPv6Rig(t, true, fake)
	_ = fake.Up(r.srv.relayInterface())
	r.srv.startRelay6()
	if fake.Snapshot().Forward6 || len(r.logs) != 1 || !strings.Contains(r.logs[0], "IPv6 inside the mesh is off") {
		t.Errorf("relay without IPv6: forward6 %v, logs %q", fake.Snapshot().Forward6, r.logs)
	}
}

func TestPhoneConfigIPv6(t *testing.T) {
	r := newIPv6Rig(t, true, wgctl.NewFake(nil, nil, ""))
	r.join("pve1", []string{"192.168.50.0/24", "2001:db8:50::/48"}, false)
	conf, err := r.srv.AddStatic("phone", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address = 10.144.0.3/32, fd77:6768::a90:3/128\n",
		"AllowedIPs = 10.144.0.0/16, fd77:6768::/64, 192.168.50.0/24, 2001:db8:50::/48\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("phone config has no %q:\n%s", want, conf)
		}
	}
	conf, err = r.srv.AddStatic("phone2", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "Address = 10.144.0.4/32, fd77:6768::a90:4/128\n") || !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0, ::/0\n") {
		t.Errorf("exit phone config:\n%s", conf)
	}
}
