package wgctl

import (
	"net/netip"
	"strings"
	"testing"
)

var testIfc6 = Interface{Name: "wgh0", Address: netip.MustParsePrefix("10.144.0.5/16"),
	Address6: netip.MustParsePrefix("fd77:6768::a90:5/64"), ListenPort: 41820, PrivateKey: "SECRETKEY"}

// linuxLog is a Linux backend whose Runner records every command and its
// stdin. fail lists the command lines that fail.
func linuxLog(fail ...string) (*Linux, *cmdLog) {
	c := &cmdLog{answer: func(line string, _ int) (string, error) {
		for _, f := range fail {
			if line == f {
				return "", errFake
			}
		}
		if strings.Contains(line, " -C ") || line == "ip link show dev wgh0" {
			return "", errFake // no jump yet, no interface yet
		}
		return "", nil
	}}
	return &Linux{Run: c.run}, c
}

// TestLinuxIPv6Commands checks the exact command sequence of a dual-stack
// interface: address, routes, exit node, forwarding and the access filter
// in both families, and that Down undoes all of it.
func TestLinuxIPv6Commands(t *testing.T) {
	l, c := linuxLog()
	if err := l.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	if err := l.IPv6Off("wgh0"); err != nil {
		t.Fatalf("IPv6Off = %v", err)
	}
	expect(t, "up", c.take(), []string{
		"ip link show dev wgh0",
		"ip link add dev wgh0 type wireguard",
		"ip address replace 10.144.0.5/16 dev wgh0",
		"ip link set dev wgh0 mtu 1280 up",
		"test -d /proc/sys/net/ipv6",
		"ip -6 address replace fd77:6768::a90:5/64 dev wgh0",
	})
	if err := l.SetRoutes("wgh0", []string{"192.168.50.0/24", "2001:db8:50::/48"}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetRoutes("wgh0", []string{"192.168.50.0/24"}); err != nil {
		t.Fatal(err)
	}
	expect(t, "routes", c.take(), []string{
		"ip route replace 192.168.50.0/24 dev wgh0 metric 1000",
		"ip -6 route replace 2001:db8:50::/48 dev wgh0 metric 1000",
		"ip -6 route del 2001:db8:50::/48 dev wgh0 metric 1000",
	})
	if err := l.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	if err := l.SetExit("wgh0", true); err != nil { // no-op
		t.Fatal(err)
	}
	expect(t, "exit", c.take(), []string{
		"ip -4 route replace default dev wgh0 table 5767",
		"ip -4 rule add not fwmark 0x5767 table 5767 priority 5767",
		"ip -4 rule add table main suppress_prefixlength 0 priority 5766",
		"ip -6 route replace default dev wgh0 table 5767",
		"ip -6 rule add not fwmark 0x5767 table 5767 priority 5767",
		"ip -6 rule add table main suppress_prefixlength 0 priority 5766",
	})
	if err := l.SetForward("wgh0", "10.144.0.0/16", true); err != nil {
		t.Fatal(err)
	}
	if err := l.SetForward6("wgh0", "fd77:6768::/64", true); err != nil {
		t.Fatal(err)
	}
	if err := l.SetForward6("wgh0", "fd77:6768::/64", true); err != nil { // no-op
		t.Fatal(err)
	}
	expect(t, "forward", c.take(), []string{
		"sysctl -q -w net.ipv4.ip_forward=1",
		"iptables -w -A FORWARD -i wgh0 -j ACCEPT -m comment --comment wgh",
		"iptables -w -A FORWARD -o wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh",
		"iptables -w -t nat -A POSTROUTING -s 10.144.0.0/16 ! -o wgh0 -j MASQUERADE -m comment --comment wgh",
		"sysctl -q -w net.ipv6.conf.all.forwarding=1",
		"ip6tables -w -A FORWARD -i wgh0 -j ACCEPT -m comment --comment wgh",
		"ip6tables -w -A FORWARD -o wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh",
		"ip6tables -w -t nat -A POSTROUTING -s fd77:6768::/64 ! -o wgh0 -j MASQUERADE -m comment --comment wgh",
	})

	rules := []FilterRule{
		{Src: "10.144.0.1/32"}, {Src: "fd77:6768::a90:1/128"},
		{Src: "10.144.0.3/32"}, {Src: "fd77:6768::a90:3/128"},
		{Src: "2001:db8:50::/48"},
		{Src: "10.144.0.3/32", Dst: "fd77:6768::a90:5/128"}, // mixed: matches nothing
	}
	if err := l.SetFilter("wgh0", FilterInbound, rules); err != nil {
		t.Fatal(err)
	}
	if err := l.SetFilter("wgh0", FilterInbound, rules); err != nil { // no-op
		t.Fatal(err)
	}
	expect(t, "filter", c.take(), []string{
		"iptables-restore -w --noflush",
		"iptables -w -C INPUT -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -I INPUT 1 -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -C FORWARD -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -I FORWARD 1 -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables-restore -w --noflush",
		"ip6tables -w -C INPUT -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables -w -I INPUT 1 -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables -w -C FORWARD -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables -w -I FORWARD 1 -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
	})
	want4 := `*filter
:WGH-wgh0 - [0:0]
-A WGH-wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -s 10.144.0.1/32 -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -s 10.144.0.3/32 -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -j DROP -m comment --comment wgh
COMMIT
`
	want6 := `*filter
:WGH-wgh0 - [0:0]
-A WGH-wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -s fd77:6768::a90:1/128 -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -s fd77:6768::a90:3/128 -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -s 2001:db8:50::/48 -j ACCEPT -m comment --comment wgh
-A WGH-wgh0 -j DROP -m comment --comment wgh
COMMIT
`
	if got := string(c.stdin["iptables-restore -w --noflush"]); got != want4 {
		t.Errorf("IPv4 chain:\n%s\nwant:\n%s", got, want4)
	}
	if got := string(c.stdin["ip6tables-restore -w --noflush"]); got != want6 {
		t.Errorf("IPv6 chain:\n%s\nwant:\n%s", got, want6)
	}

	// No rules at all still closes IPv6: both chains end in DROP.
	if err := l.SetFilter("wgh0", FilterInbound, []FilterRule{}); err != nil {
		t.Fatal(err)
	}
	expect(t, "empty filter", c.take(), []string{"iptables-restore -w --noflush", "ip6tables-restore -w --noflush"})
	if got := string(c.stdin["ip6tables-restore -w --noflush"]); !strings.HasSuffix(got, "-A WGH-wgh0 -j DROP -m comment --comment wgh\nCOMMIT\n") ||
		strings.Contains(got, "-s ") {
		t.Errorf("empty IPv6 chain:\n%s", got)
	}

	if err := l.Down("wgh0"); err != nil {
		t.Fatal(err)
	}
	expect(t, "down", c.take(), []string{
		"ip -4 rule del priority 5767",
		"ip -4 rule del priority 5766",
		"ip -4 route flush table 5767",
		"ip -6 rule del priority 5767",
		"ip -6 rule del priority 5766",
		"ip -6 route flush table 5767",
		"iptables -w -D FORWARD -i wgh0 -j ACCEPT -m comment --comment wgh",
		"iptables -w -D FORWARD -o wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh",
		"iptables -w -t nat -D POSTROUTING -s 10.144.0.0/16 ! -o wgh0 -j MASQUERADE -m comment --comment wgh",
		"ip6tables -w -D FORWARD -i wgh0 -j ACCEPT -m comment --comment wgh",
		"ip6tables -w -D FORWARD -o wgh0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment wgh",
		"ip6tables -w -t nat -D POSTROUTING -s fd77:6768::/64 ! -o wgh0 -j MASQUERADE -m comment --comment wgh",
		"iptables -w -D INPUT -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -D FORWARD -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"iptables -w -F WGH-wgh0",
		"iptables -w -X WGH-wgh0",
		"ip6tables -w -D INPUT -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables -w -D FORWARD -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables -w -F WGH-wgh0",
		"ip6tables -w -X WGH-wgh0",
		"ip link show dev wgh0",
	})
}

// TestLinuxRelayFilterIPv6: the relay's filter, which only covers traffic
// between peers, is kept for IPv6 too.
func TestLinuxRelayFilterIPv6(t *testing.T) {
	l, c := linuxLog()
	relay := Interface{Name: "wgh-relay", Address: netip.MustParsePrefix("10.144.0.1/16"),
		Address6: netip.MustParsePrefix("fd77:6768::a90:1/64"), ListenPort: 51820, PrivateKey: "K"}
	if err := l.Up(relay); err != nil {
		t.Fatal(err)
	}
	c.take()
	rules := []FilterRule{{Src: "10.144.0.2/32", Dst: "10.144.0.3/32"}, {Src: "fd77:6768::a90:2/128", Dst: "fd77:6768::a90:3/128"}}
	if err := l.SetFilter("wgh-relay", FilterRelayed, rules); err != nil {
		t.Fatal(err)
	}
	expect(t, "relay filter", c.take(), []string{
		"iptables-restore -w --noflush",
		"iptables -w -C FORWARD -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
		"iptables -w -I FORWARD 1 -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
		"ip6tables-restore -w --noflush",
		"ip6tables -w -C FORWARD -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
		"ip6tables -w -I FORWARD 1 -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
	})
	if got := string(c.stdin["ip6tables-restore -w --noflush"]); !strings.Contains(got,
		"-A WGH-wgh-relay -s fd77:6768::a90:2/128 -d fd77:6768::a90:3/128 -j ACCEPT -m comment --comment wgh\n") ||
		strings.Contains(got, "10.144.") {
		t.Errorf("IPv6 relay chain:\n%s", got)
	}
	if err := l.SetFilter("wgh-relay", FilterRelayed, nil); err != nil {
		t.Fatal(err)
	}
	expect(t, "relay filter off", c.take(), []string{
		"iptables -w -D FORWARD -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
		"iptables -w -F WGH-wgh-relay",
		"iptables -w -X WGH-wgh-relay",
		"ip6tables -w -D FORWARD -i wgh-relay -o wgh-relay -j WGH-wgh-relay -m comment --comment wgh",
		"ip6tables -w -F WGH-wgh-relay",
		"ip6tables -w -X WGH-wgh-relay",
	})
}

// TestLinuxIPv6FilterFailureRetried: an IPv6 chain that fails is reported
// and tried again on the next call, even with the same rules.
func TestLinuxIPv6FilterFailureRetried(t *testing.T) {
	failing := true
	c := &cmdLog{answer: func(line string, _ int) (string, error) {
		if strings.Contains(line, " -C ") || line == "ip link show dev wgh0" || (failing && line == "ip6tables-restore -w --noflush") {
			return "", errFake
		}
		return "", nil
	}}
	l := &Linux{Run: c.run}
	if err := l.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	rules := []FilterRule{{Src: "fd77:6768::a90:1/128"}}
	if err := l.SetFilter("wgh0", FilterInbound, rules); err == nil || !strings.Contains(err.Error(), "IPv6 access filter") {
		t.Fatalf("IPv6 failure: %v", err)
	}
	failing = false
	c.take()
	if err := l.SetFilter("wgh0", FilterInbound, rules); err != nil {
		t.Fatal(err)
	}
	expect(t, "retry", c.take(), []string{
		"iptables-restore -w --noflush",
		"ip6tables-restore -w --noflush",
		"ip6tables -w -C INPUT -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables -w -I INPUT 1 -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables -w -C FORWARD -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
		"ip6tables -w -I FORWARD 1 -i wgh0 -j WGH-wgh0 -m comment --comment wgh",
	})
}

// TestLinuxIPv6Disabled: with IPv6 off on the host, Up still succeeds, says
// why IPv6 is off and every later step stays IPv4 only.
func TestLinuxIPv6Disabled(t *testing.T) {
	for _, fail := range []string{"test -d /proc/sys/net/ipv6", "ip -6 address replace fd77:6768::a90:5/64 dev wgh0"} {
		l, c := linuxLog(fail)
		if err := l.Up(testIfc6); err != nil {
			t.Fatalf("Up failed because of IPv6 (%s): %v", fail, err)
		}
		if l.IPv6Off("wgh0") == nil {
			t.Errorf("%s: IPv6Off is nil", fail)
		}
		if err := l.SetRoutes("wgh0", []string{"192.168.50.0/24", "2001:db8:50::/48"}); err != nil {
			t.Fatal(err)
		}
		if err := l.SetExit("wgh0", true); err != nil {
			t.Fatal(err)
		}
		if err := l.SetForward6("wgh0", "fd77:6768::/64", true); err != nil {
			t.Fatal(err)
		}
		if err := l.SetFilter("wgh0", FilterInbound, []FilterRule{{Src: "fd77:6768::a90:1/128"}}); err != nil {
			t.Fatal(err)
		}
		if err := l.Down("wgh0"); err != nil {
			t.Fatal(err)
		}
		for i, line := range c.take() {
			if line == fail || line == "test -d /proc/sys/net/ipv6" { // the probes
				continue
			}
			if strings.Contains(line, "ip -6") || strings.Contains(line, "ip6tables") || strings.Contains(line, "ipv6") ||
				strings.Contains(line, "fd77") || strings.Contains(line, "2001:db8") {
				t.Errorf("%s: IPv6 command %d with IPv6 off: %s", fail, i, line)
			}
		}
	}
}

// TestLinuxIPv6ExitFailure: when the IPv6 half of the exit node can't be
// set up, the IPv4 half is taken down too, so IPv6 doesn't leak past it.
func TestLinuxIPv6ExitFailure(t *testing.T) {
	l, c := linuxLog("ip -6 rule add not fwmark 0x5767 table 5767 priority 5767")
	if err := l.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	c.take()
	if err := l.SetExit("wgh0", true); err == nil {
		t.Fatal("IPv6 exit failure not reported")
	}
	expect(t, "rollback", c.take(), []string{
		"ip -4 route replace default dev wgh0 table 5767",
		"ip -4 rule add not fwmark 0x5767 table 5767 priority 5767",
		"ip -4 rule add table main suppress_prefixlength 0 priority 5766",
		"ip -6 route replace default dev wgh0 table 5767",
		"ip -6 rule add not fwmark 0x5767 table 5767 priority 5767",
		"ip -4 rule del priority 5767",
		"ip -4 rule del priority 5766",
		"ip -4 route flush table 5767",
		"ip -6 rule del priority 5767",
		"ip -6 rule del priority 5766",
		"ip -6 route flush table 5767",
	})
	if l.exit || l.exit6 {
		t.Error("exit left on")
	}
}

// TestLinuxIPv6ExitAddedLater: an exit node turned on before the interface
// got IPv6 gains the IPv6 half on the next call.
func TestLinuxIPv6ExitAddedLater(t *testing.T) {
	l, c := linuxLog()
	if err := l.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	if err := l.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	if err := l.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	c.take()
	if err := l.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	expect(t, "IPv6 half", c.take(), []string{
		"ip -6 route replace default dev wgh0 table 5767",
		"ip -6 rule add not fwmark 0x5767 table 5767 priority 5767",
		"ip -6 rule add table main suppress_prefixlength 0 priority 5766",
	})
}

func TestSplitFilterRules(t *testing.T) {
	v4, v6 := SplitFilterRules([]FilterRule{
		{Src: "10.144.0.2/32"}, {Dst: "fd77:6768::a90:3/128"}, {}, {Src: "10.0.0.0/8", Dst: "2001:db8::/32"},
	})
	if len(v4) != 2 || v4[0].Src != "10.144.0.2/32" || v4[1] != (FilterRule{}) {
		t.Errorf("v4 = %+v", v4)
	}
	if len(v6) != 2 || v6[0].Dst != "fd77:6768::a90:3/128" || v6[1] != (FilterRule{}) {
		t.Errorf("v6 = %+v", v6)
	}
	if v4, v6 := SplitFilterRules(nil); v4 == nil || v6 == nil {
		t.Error("empty split is nil: that would mean no filter")
	}
}

func TestFakeIPv6(t *testing.T) {
	f := NewFake(nil, nil, "")
	if err := f.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	_ = f.SetForward6("wgh0", "fd77:6768::/64", true)
	if s := f.Snapshot(); s.Address6 != testIfc6.Address6 || !s.Forward6 || f.IPv6Off("wgh0") != nil {
		t.Fatalf("snapshot %+v", s)
	}
	off := NewFake(nil, nil, "")
	off.NoIPv6 = true
	if err := off.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	_ = off.SetForward6("wgh0", "fd77:6768::/64", true)
	if s := off.Snapshot(); s.Address6.IsValid() || s.Forward6 || IPv6Off(off, "wgh0") == nil {
		t.Fatalf("no-IPv6 snapshot %+v", s)
	}
	var _ Forwarder6 = &Linux{}
	var _ IPv6Reporter = &Linux{}
	var _ IPv6Reporter = &Darwin{}
	if IPv6Off(Unsupported{}, "wgh0") != nil {
		t.Error("a backend without IPv6Reporter reports IPv6 off")
	}
}
