package coord

import (
	"strings"
	"testing"
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
}
