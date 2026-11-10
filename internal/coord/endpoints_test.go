package coord

import (
	"strings"
	"testing"

	"github.com/overspend1/wgh/internal/mesh"
)

func TestEndpointsFor(t *testing.T) {
	d := &device{RelayEndpoint: "198.51.100.7:41820", SeenIP: "198.51.100.7", ListenPort: 41820,
		Local: []string{"192.168.1.20:41820", "[2001:db8:1::20]:41820"}}
	v4only := &device{SeenIP: "203.0.113.9", Local: []string{"10.0.0.5:41820"}}
	dual := &device{SeenIP: "203.0.113.9", Local: []string{"10.0.0.5:41820", "[2001:db8:2::5]:41820"}}
	sameLAN := &device{SeenIP: "198.51.100.7", Local: []string{"192.168.1.30:41820"}}
	cases := []struct {
		name   string
		viewer *device
		want   string
	}{
		{"viewer without IPv6 skips IPv6", v4only, "198.51.100.7:41820 192.168.1.20:41820"},
		{"both with IPv6: IPv6 first", dual, "[2001:db8:1::20]:41820 198.51.100.7:41820 192.168.1.20:41820"},
		{"same LAN: LAN first", sameLAN, "192.168.1.20:41820 198.51.100.7:41820"},
	}
	for _, c := range cases {
		if got := strings.Join(endpointsFor(d, c.viewer), " "); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	// A device seen over IPv6: its public guess is IPv6 and only offered to IPv6 viewers.
	d6 := &device{SeenIP: "2001:db8:1::20", ListenPort: 41820}
	if got := endpointsFor(d6, v4only); len(got) != 0 {
		t.Errorf("IPv6-only guess offered to an IPv4 viewer: %v", got)
	}
	if got := endpointsFor(d6, dual); len(got) != 1 || got[0] != "[2001:db8:1::20]:41820" {
		t.Errorf("IPv6 viewer: %v", got)
	}
	if !sameSite("2001:db8:1::20", "2001:db8:1::99") || sameSite("2001:db8:1::20", "2001:db8:2::20") {
		t.Error("sameSite /64")
	}

	// A router-mapped port leads the public guesses, ahead of what the
	// relay saw; IPv6 still goes first and a shared LAN still wins.
	dm := *d
	dm.Mapped = "198.51.100.7:61000"
	for _, c := range []struct {
		name   string
		viewer *device
		want   string
	}{
		{"mapped first among public", v4only, "198.51.100.7:61000 198.51.100.7:41820 192.168.1.20:41820"},
		{"IPv6 before mapped", dual, "[2001:db8:1::20]:41820 198.51.100.7:61000 198.51.100.7:41820 192.168.1.20:41820"},
		{"same LAN before mapped", sameLAN, "192.168.1.20:41820 198.51.100.7:61000 198.51.100.7:41820"},
	} {
		if got := strings.Join(endpointsFor(&dm, c.viewer), " "); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	for in, want := range map[string]string{"203.0.113.5:41820": "203.0.113.5:41820", "[::ffff:203.0.113.5]:9": "203.0.113.5:9",
		"192.168.1.1:41820": "", "100.64.0.9:41820": "", "203.0.113.5:0": "", "junk": "", "[2001:db8::1]:41820": ""} {
		if got := usableMapped(in); got != want {
			t.Errorf("usableMapped(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMappedHeartbeat(t *testing.T) {
	r := newACLRig(t, "")
	r.join("laptop", nil, false)
	r.join("desk", nil, false)
	beat := func(mapped string) {
		t.Helper()
		if err := r.srv.Update(r.keys["laptop"], mesh.UpdateRequest{ListenPort: 41820, Mapped: mapped}, "198.51.100.7"); err != nil {
			t.Fatal(err)
		}
	}
	beat("203.0.113.5:41820")
	var peer mesh.Node
	for _, p := range r.netmap("desk").Peers {
		if p.Name == "laptop" {
			peer = p
		}
	}
	if peer.Mapped != "203.0.113.5:41820" || len(peer.Endpoints) == 0 || peer.Endpoints[0] != "203.0.113.5:41820" {
		t.Fatalf("desk sees laptop as %+v", peer)
	}
	// A private value clears it.
	beat("10.0.0.1:41820")
	for _, d := range r.srv.Status().Devices {
		if d.Name == "laptop" && d.Mapped != "" {
			t.Fatalf("private mapping kept: %q", d.Mapped)
		}
	}
}
