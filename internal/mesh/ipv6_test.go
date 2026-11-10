package mesh

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestValidRoutesIPv6(t *testing.T) {
	if err := ValidRoutes([]string{"2001:db8:1::/48", "fd00:50::/64", "192.168.1.0/24"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"::/0", "2001:db8::1/48", "::ffff:10.0.0.0/104", "fd77:6768::/64", "fd77::/16", "fd77:6768::a90:5/128"} {
		if ValidRoutes([]string{bad}) == nil {
			t.Errorf("ValidRoutes(%q) succeeded", bad)
		}
	}
	if err := ValidRoutes([]string{"::/0"}); err == nil || !strings.Contains(err.Error(), "--advertise-exit") {
		t.Errorf("::/0: %v", err)
	}
}

func TestAddr6(t *testing.T) {
	for in, want := range map[string]string{
		"10.144.0.5":      "fd77:6768::a90:5",
		"10.144.0.1":      "fd77:6768::a90:1",
		"10.144.255.254":  "fd77:6768::a90:fffe",
		"192.168.1.10":    "fd77:6768::c0a8:10a",
		"2001:db8::1":     "",
		"not an address":  "",
		"":                "",
		"::ffff:10.0.0.1": "",
	} {
		if got := Addr6(in); got != want {
			t.Errorf("Addr6(%q) = %q, want %q", in, got, want)
		}
	}
	p := netip.MustParsePrefix(DefaultSubnet6)
	if p.Bits() != 64 || p != p.Masked() || !p.Contains(netip.MustParseAddr(Addr6("10.144.0.5"))) {
		t.Errorf("DefaultSubnet6 %s", p)
	}
}

// TestNetMapWithoutIPv6: a map from a coordinator before IPv6 has none of
// the new fields, and one without IPv6 renders none of them.
func TestNetMapWithoutIPv6(t *testing.T) {
	old := `{"version":3,"subnet":"10.144.0.0/16","domain":"wgh","self":{"id":"a","name":"laptop","address":"10.144.0.2","public_key":"K","online":true},` +
		`"relay":{"name":"relay","address":"10.144.0.1","public_key":"R","endpoint":"relay.example:51820"},"peers":[]}`
	var nm NetMap
	if err := json.Unmarshal([]byte(old), &nm); err != nil {
		t.Fatal(err)
	}
	if nm.Subnet6 != "" || nm.Self.Address6 != "" || nm.Relay.Address6 != "" {
		t.Fatalf("old map read with IPv6: %+v", nm)
	}
	b, _ := json.Marshal(NetMap{Subnet: DefaultSubnet, Relay: &Relay{}, Peers: []Node{{}}})
	if strings.Contains(string(b), "address6") || strings.Contains(string(b), "subnet6") {
		t.Errorf("empty IPv6 fields rendered: %s", b)
	}
}
