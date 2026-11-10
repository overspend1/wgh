package ipam

import (
	"errors"
	"net/netip"
	"testing"
)

func addrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestParseSubnet(t *testing.T) {
	p, err := ParseSubnet("10.8.0.77/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != "10.8.0.0/24" {
		t.Errorf("masked subnet = %s, want 10.8.0.0/24", got)
	}
	for _, bad := range []string{"nope", "10.8.0.0", "fd00::/64", "10.8.0.0/31", "10.8.0.0/32"} {
		if _, err := ParseSubnet(bad); err == nil {
			t.Errorf("ParseSubnet(%q) succeeded, want error", bad)
		}
	}
}

func TestBroadcast(t *testing.T) {
	cases := map[string]string{
		"10.8.0.0/24":    "10.8.0.255",
		"192.168.4.0/30": "192.168.4.3",
		"10.0.0.0/8":     "10.255.255.255",
		"172.16.8.0/22":  "172.16.11.255",
	}
	for cidr, want := range cases {
		if got := Broadcast(netip.MustParsePrefix(cidr)).String(); got != want {
			t.Errorf("Broadcast(%s) = %s, want %s", cidr, got, want)
		}
	}
}

func TestNextSkipsUsedAndFillsGaps(t *testing.T) {
	subnet := netip.MustParsePrefix("10.8.0.0/24")

	got, err := Next(subnet, nil)
	if err != nil || got.String() != "10.8.0.1" {
		t.Fatalf("Next(empty) = %v, %v; want 10.8.0.1", got, err)
	}

	got, err = Next(subnet, addrs(t, "10.8.0.1", "10.8.0.2", "10.8.0.3"))
	if err != nil || got.String() != "10.8.0.4" {
		t.Fatalf("Next(1-3 used) = %v, %v; want 10.8.0.4", got, err)
	}

	// A removed peer leaves a gap that is reused first.
	got, err = Next(subnet, addrs(t, "10.8.0.1", "10.8.0.3", "10.8.0.4"))
	if err != nil || got.String() != "10.8.0.2" {
		t.Fatalf("Next(gap at .2) = %v, %v; want 10.8.0.2", got, err)
	}
}

func TestNextExhausted(t *testing.T) {
	// A /30 has exactly two usable hosts.
	subnet := netip.MustParsePrefix("10.9.0.0/30")
	if _, err := Next(subnet, addrs(t, "10.9.0.1", "10.9.0.2")); !errors.Is(err, ErrExhausted) {
		t.Fatalf("Next on full /30: err = %v, want ErrExhausted", err)
	}
	got, err := Next(subnet, addrs(t, "10.9.0.1"))
	if err != nil || got.String() != "10.9.0.2" {
		t.Fatalf("Next(/30, .1 used) = %v, %v; want 10.9.0.2", got, err)
	}
}

func TestNextNeverReturnsBroadcast(t *testing.T) {
	subnet := netip.MustParsePrefix("10.8.0.0/29") // hosts .1 to .6
	used := addrs(t, "10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4", "10.8.0.5")
	got, err := Next(subnet, used)
	if err != nil || got.String() != "10.8.0.6" {
		t.Fatalf("Next = %v, %v; want 10.8.0.6", got, err)
	}
	used = append(used, got)
	if got, err := Next(subnet, used); !errors.Is(err, ErrExhausted) {
		t.Fatalf("Next on full /29 = %v, %v; want ErrExhausted", got, err)
	}
}

func TestClaim(t *testing.T) {
	subnet := netip.MustParsePrefix("10.8.0.0/24")
	used := addrs(t, "10.8.0.1", "10.8.0.5")
	cases := []struct {
		addr string
		ok   bool
	}{
		{"10.8.0.10", true},
		{"10.8.0.5", false},   // taken
		{"10.8.0.0", false},   // network
		{"10.8.0.255", false}, // broadcast
		{"10.9.0.10", false},  // outside
		{"fd00::1", false},    // wrong family
	}
	for _, c := range cases {
		err := Claim(subnet, netip.MustParseAddr(c.addr), used)
		if (err == nil) != c.ok {
			t.Errorf("Claim(%s) err = %v, want ok=%v", c.addr, err, c.ok)
		}
	}
}
