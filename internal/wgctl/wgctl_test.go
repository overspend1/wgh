package wgctl

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseDump(t *testing.T) {
	dump := "PRIV\tPUB\t41820\t0x5767\n" +
		"PEER1\t(none)\t203.0.113.5:41820\t10.144.0.2/32\t1700000000\t1234\t5678\t25\n" +
		"PEER2\t(none)\t(none)\t(none)\t0\t0\t0\t25\n"
	stats, err := ParseDump([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("got %d peers", len(stats))
	}
	if stats[0].Endpoint != "203.0.113.5:41820" || stats[0].RxBytes != 1234 || stats[0].TxBytes != 5678 ||
		!stats[0].LastHandshake.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("peer 1 = %+v", stats[0])
	}
	if stats[1].Endpoint != "" || !stats[1].LastHandshake.IsZero() {
		t.Errorf("peer 2 = %+v", stats[1])
	}
}

func TestConfigRender(t *testing.T) {
	got := string(Config(Interface{Name: "wgh0", PrivateKey: "K", ListenPort: 41820}, []Peer{
		{PublicKey: "B", AllowedIPs: nil, Keepalive: 25, Endpoint: "198.51.100.2:41820"},
		{PublicKey: "A", AllowedIPs: []string{"10.144.0.3/32", "192.168.1.0/24"}, Keepalive: 25},
	}))
	want := `[Interface]
PrivateKey = K
ListenPort = 41820
FwMark = 0x5767

[Peer]
PublicKey = A
AllowedIPs = 10.144.0.3/32, 192.168.1.0/24
PersistentKeepalive = 25

[Peer]
PublicKey = B
Endpoint = 198.51.100.2:41820
PersistentKeepalive = 25
`
	if got != want {
		t.Fatalf("config:\n%s\nwant:\n%s", got, want)
	}
}

// TestLinuxCommands checks the exact commands without running any of them.
func TestLinuxCommands(t *testing.T) {
	var ran []string
	l := &Linux{Run: func(stdin []byte, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		ran = append(ran, line)
		if line == "ip link show dev wgh0" && len(ran) == 1 {
			return nil, errFake
		}
		return nil, nil
	}}
	ifc := Interface{Name: "wgh0", Address: netip.MustParsePrefix("10.144.0.5/16"), ListenPort: 41820, PrivateKey: "K"}
	if err := l.Up(ifc); err != nil {
		t.Fatal(err)
	}
	if err := l.SetPeers(ifc, nil); err != nil {
		t.Fatal(err)
	}
	if err := l.SetRoutes("wgh0", []string{"192.168.1.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetRoutes("wgh0", nil); err != nil {
		t.Fatal(err)
	}
	if err := l.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	if err := l.SetForward("wgh0", "10.144.0.0/16", true); err != nil {
		t.Fatal(err)
	}
	if err := l.Down("wgh0"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip link show dev wgh0",
		"ip link add dev wgh0 type wireguard",
		"ip address replace 10.144.0.5/16 dev wgh0",
		"ip link set dev wgh0 mtu 1280 up",
		"wg syncconf wgh0 /dev/stdin",
		"ip route replace 192.168.1.0/24 dev wgh0 metric 1000",
		"ip route del 192.168.1.0/24 dev wgh0 metric 1000",
		"ip -4 route replace default dev wgh0 table 5767",
		"ip -4 rule add not fwmark 0x5767 table 5767 priority 5767",
		"ip -4 rule add table main suppress_prefixlength 0 priority 5766",
		"sysctl -q -w net.ipv4.ip_forward=1",
		"iptables -w -A FORWARD -i wgh0 -j ACCEPT -m comment --comment wgh",
		"iptables -w -A FORWARD -o wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh",
		"iptables -w -t nat -A POSTROUTING -s 10.144.0.0/16 ! -o wgh0 -j MASQUERADE -m comment --comment wgh",
		"ip -4 rule del priority 5767",
		"ip -4 rule del priority 5766",
		"ip -4 route flush table 5767",
		"iptables -w -D FORWARD -i wgh0 -j ACCEPT -m comment --comment wgh",
		"iptables -w -D FORWARD -o wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh",
		"iptables -w -t nat -D POSTROUTING -s 10.144.0.0/16 ! -o wgh0 -j MASQUERADE -m comment --comment wgh",
		"ip link show dev wgh0",
		"ip link del dev wgh0",
	}
	if strings.Join(ran, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\n\nwant:\n%s", strings.Join(ran, "\n"), strings.Join(want, "\n"))
	}
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

var errFake = fakeErr("Device does not exist")
