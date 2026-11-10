package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/wgctl"
)

func TestMeshIPv6EndToEnd(t *testing.T) {
	r := newRig(t)
	a := r.join("laptop", "192.168.1.10", nil, false)
	b := r.join("pve1", "192.168.1.20", []string{"192.168.50.0/24", "2001:db8:50::/48"}, true)
	eventually(t, "direct path laptop->pve1", func() bool { return peerStatus(a, "pve1").Path == PathDirect })

	// The interface gets both addresses once the netmap says IPv6.
	eventually(t, "IPv6 address", func() bool { return a.fake.Snapshot().Address6.String() == "fd77:6768::a90:2/64" })
	snap := a.fake.Snapshot()
	if snap.Address.String() != "10.144.0.2/16" {
		t.Errorf("IPv4 address = %s", snap.Address)
	}
	// The direct peer has its /32 and /128.
	eventually(t, "pve1's /128", func() bool {
		p, _ := a.fake.Snapshot().Peer(b.pub)
		return slices.Contains(p.AllowedIPs, "10.144.0.3/32") && slices.Contains(p.AllowedIPs, "fd77:6768::a90:3/128")
	})
	relayPub := r.srv.Status().Relay.PublicKey
	rp, _ := a.fake.Snapshot().Peer(relayPub)
	if !slices.Contains(rp.AllowedIPs, "10.144.0.0/16") || !slices.Contains(rp.AllowedIPs, "fd77:6768::/64") {
		t.Fatalf("relay peer = %+v", rp)
	}

	// Status shows the IPv6 addresses.
	st := a.a.Status()
	if st.Address6 != "fd77:6768::a90:2" || st.Subnet6 != mesh.DefaultSubnet6 {
		t.Errorf("status address6 %q subnet6 %q", st.Address6, st.Subnet6)
	}
	if p := peerStatus(a, "pve1"); p.Address6 != "fd77:6768::a90:3" {
		t.Errorf("pve1 address6 = %q", p.Address6)
	}
	if p := peerStatus(a, "relay"); p.Address6 != "fd77:6768::a90:1" {
		t.Errorf("relay address6 = %q", p.Address6)
	}

	// The hosts file has a second line per device.
	eventually(t, "hosts file with IPv6", func() bool {
		h, _ := os.ReadFile(a.hosts)
		s := string(h)
		return strings.Contains(s, "10.144.0.3\tpve1 pve1.wgh\nfd77:6768::a90:3\tpve1 pve1.wgh\n") &&
			strings.Contains(s, "fd77:6768::a90:1\trelay relay.wgh") && strings.Contains(s, "fd77:6768::a90:2\tlaptop laptop.wgh")
	})

	// pve1 offers an exit node, so it forwards and NATs IPv6 too; laptop
	// offers nothing and forwards nothing.
	eventually(t, "pve1 forwards IPv6", func() bool { s := b.fake.Snapshot(); return s.Forward && s.Forward6 })
	if s := a.fake.Snapshot(); s.Forward || s.Forward6 {
		t.Error("laptop forwards")
	}

	// The approved IPv6 route lands on the direct peer and in the routes.
	if _, _, err := r.srv.Approve("pve1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "IPv6 route", func() bool {
		p, _ := a.fake.Snapshot().Peer(b.pub)
		return slices.Contains(a.fake.Snapshot().Routes, "2001:db8:50::/48") && slices.Contains(p.AllowedIPs, "2001:db8:50::/48")
	})

	// With pve1 as the exit node both default routes go to it.
	eventually(t, "exit approved", func() bool { return peerStatus(a, "pve1").Exit })
	if err := a.a.SetExitNode("pve1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "exit on with ::/0", func() bool {
		p, _ := a.fake.Snapshot().Peer(b.pub)
		return a.fake.Snapshot().Exit && slices.Contains(p.AllowedIPs, "0.0.0.0/0") && slices.Contains(p.AllowedIPs, "::/0")
	})

	// The relay as exit node: both default routes go to the relay.
	if err := a.a.SetExitNode("relay"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "relay exit with ::/0", func() bool {
		p, _ := a.fake.Snapshot().Peer(relayPub)
		return slices.Contains(p.AllowedIPs, "0.0.0.0/0") && slices.Contains(p.AllowedIPs, "::/0")
	})
}

// stripIPv6 is a transport that turns every netmap into what a coordinator
// from before IPv6 sends: no Subnet6 and no Address6 anywhere.
type stripIPv6 struct{ base http.RoundTripper }

func (s stripIPv6) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := s.base.RoundTrip(req)
	if err != nil || req.URL.Path != "/v1/netmap" || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var nm mesh.NetMap
	if err := json.Unmarshal(body, &nm); err != nil {
		return nil, err
	}
	nm.Subnet6, nm.Self.Address6 = "", ""
	if nm.Relay != nil {
		nm.Relay.Address6 = ""
	}
	for i := range nm.Peers {
		nm.Peers[i].Address6 = ""
	}
	out, _ := json.Marshal(nm)
	if bytes.Contains(out, []byte("fd77")) || bytes.Contains(out, []byte("subnet6")) {
		panic("IPv6 left in the stripped netmap: " + string(out))
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Del("Content-Length")
	return resp, nil
}

// TestOldCoordinatorIPv4Only: with a netmap that has no IPv6, the agent
// configures exactly what it did before IPv6.
func TestOldCoordinatorIPv4Only(t *testing.T) {
	r := newRig(t)
	r.opts = func(_ string, o *Options) {
		o.HTTP = func(c *Client) { c.HTTP.Transport = stripIPv6{base: c.HTTP.Transport} }
	}
	a := r.join("laptop", "192.168.1.10", nil, false)
	b := r.join("pve1", "192.168.1.20", []string{"192.168.50.0/24"}, true)
	eventually(t, "direct path", func() bool { return peerStatus(a, "pve1").Path == PathDirect })
	if _, _, err := r.srv.Approve("pve1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "exit approved", func() bool { return peerStatus(a, "pve1").Exit })
	if err := a.a.SetExitNode("pve1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "exit on", func() bool { return a.fake.Snapshot().Exit })
	eventually(t, "hosts file", func() bool {
		h, _ := os.ReadFile(a.hosts)
		return strings.Contains(string(h), "10.144.0.3\tpve1 pve1.wgh")
	})
	for _, d := range []*dev{a, b} {
		s := d.fake.Snapshot()
		if s.Address6.IsValid() || s.Forward6 {
			t.Errorf("IPv6 configured from an IPv4-only netmap: %+v", s)
		}
		for _, p := range s.Peers {
			for _, ip := range p.AllowedIPs {
				if strings.Contains(ip, ":") {
					t.Errorf("IPv6 allowed IP %s on peer %s", ip, p.PublicKey)
				}
			}
		}
	}
	p, _ := a.fake.Snapshot().Peer(b.pub)
	if want := []string{"0.0.0.0/0", "10.144.0.3/32", "192.168.50.0/24"}; !slices.Equal(p.AllowedIPs, want) {
		t.Errorf("pve1 allowed IPs = %v, want %v", p.AllowedIPs, want)
	}
	h, _ := os.ReadFile(a.hosts)
	if strings.Contains(string(h), ":") {
		t.Errorf("IPv6 in the hosts file:\n%s", h)
	}
	if st := a.a.Status(); st.Address6 != "" || st.Subnet6 != "" {
		t.Errorf("status shows IPv6: %q %q", st.Address6, st.Subnet6)
	}
}

// TestIPv6DisabledHost: a host whose backend can't add the IPv6 address
// keeps working over IPv4 and says so once.
func TestIPv6DisabledHost(t *testing.T) {
	r := newRig(t)
	var logs logLines
	r.opts = func(name string, o *Options) {
		if name == "laptop" {
			o.Logf = logs.logf
		}
	}
	a := r.joinWith("laptop", "192.168.1.10", nil, false, func(f *wgctl.Fake) wgctl.Backend {
		f.NoIPv6 = true
		return f
	})
	b := r.join("pve1", "192.168.1.20", nil, false)
	eventually(t, "direct path", func() bool { return peerStatus(a, "pve1").Path == PathDirect })
	eventually(t, "IPv6 note", func() bool { return logs.count("IPv6 inside the mesh is off") == 1 })
	if a.fake.Snapshot().Address6.IsValid() {
		t.Error("IPv6 address set on a host without IPv6")
	}
	if st := a.a.Status(); st.Address6 != "" {
		t.Errorf("status shows IPv6 %q", st.Address6)
	}
	// Rotating the key brings the interface up again: still one note.
	if err := a.a.Rotate(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "pve1 sees the new key", func() bool {
		st, _ := Load(a.path)
		_, ok := b.fake.Snapshot().Peer(st.PublicKey)
		return ok
	})
	if n := logs.count("IPv6 inside the mesh is off"); n != 1 {
		t.Errorf("IPv6 note logged %d times", n)
	}
}

// TestIPv6Filter: with an access policy the device's filter lets each
// allowed peer in over IPv6 as well, and the relay; the backend sorts the
// rules into its IPv4 and IPv6 filters.
func TestIPv6Filter(t *testing.T) {
	nm := &mesh.NetMap{ACL: true, Subnet: mesh.DefaultSubnet, Subnet6: mesh.DefaultSubnet6,
		Relay: &mesh.Relay{Address: "10.144.0.1", Address6: "fd77:6768::a90:1"},
		Peers: []mesh.Node{
			{Name: "a", Address: "10.144.0.2", Address6: "fd77:6768::a90:2", CanConnect: true, Routes: []string{"2001:db8:50::/48"}},
			{Name: "b", Address: "10.144.0.3", Address6: "fd77:6768::a90:3"},
		}}
	got := srcs(inboundFilter(nm))
	if want := "10.144.0.1/32 fd77:6768::a90:1/128 10.144.0.2/32 fd77:6768::a90:2/128 2001:db8:50::/48"; got != want {
		t.Errorf("filter %q, want %q", got, want)
	}
	v4, v6 := wgctl.SplitFilterRules(inboundFilter(nm))
	if srcs(v4) != "10.144.0.1/32 10.144.0.2/32" || srcs(v6) != "fd77:6768::a90:1/128 fd77:6768::a90:2/128 2001:db8:50::/48" {
		t.Errorf("split %q | %q", srcs(v4), srcs(v6))
	}
	// An old netmap gets no rules for mesh IPv6 addresses.
	nm.Subnet6 = ""
	if got := srcs(inboundFilter(nm)); strings.Contains(got, "fd77") {
		t.Errorf("IPv6 rule from an IPv4-only netmap: %q", got)
	}
}
