package wgctl

import (
	"net/netip"
	"strings"
	"testing"
)

const routeGetDefault6 = `   route to: ::
destination: ::
       mask: default
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`

// freshDarwin6 is freshDarwin on a Mac with an IPv6 default route.
func freshDarwin6() (*Darwin, *cmdLog) {
	d, c := freshDarwin()
	base := c.answer
	c.answer = func(line string, n int) (string, error) {
		if line == "route -n get -inet6 default" {
			return routeGetDefault6, nil
		}
		return base(line, n)
	}
	return d, c
}

func TestDarwinUpIPv6(t *testing.T) {
	d, c := freshDarwin6()
	if err := d.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	expect(t, "fresh up", c.take(), []string{
		"cat /var/run/wireguard/wgh0.name",
		"mkdir -p /var/run/wireguard",
		"env -u LOG_LEVEL WG_TUN_NAME_FILE=/var/run/wireguard/wgh0.name wireguard-go utun",
		"cat /var/run/wireguard/wgh0.name",
		"ifconfig utun4 inet 10.144.0.5/16 10.144.0.5 alias",
		"ifconfig utun4 mtu 1280",
		"ifconfig utun4 up",
		"route -q -n add -inet 10.144.0.0/16 -interface utun4",
		"ifconfig utun4 inet6 fd77:6768::a90:5 prefixlen 128 alias",
		"route -q -n add -inet6 fd77:6768::/64 -interface utun4",
	})
	if err := d.IPv6Off("wgh0"); err != nil {
		t.Fatalf("IPv6Off = %v", err)
	}
	// Up again: neither mesh route is added twice.
	if err := d.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	expect(t, "second up", c.take(), []string{
		"test -S /var/run/wireguard/utun4.sock",
		"ifconfig utun4 inet 10.144.0.5/16 10.144.0.5 alias",
		"ifconfig utun4 mtu 1280",
		"ifconfig utun4 up",
		"ifconfig utun4 inet6 fd77:6768::a90:5 prefixlen 128 alias",
	})
	if err := d.Down("wgh0"); err != nil {
		t.Fatal(err)
	}
	expect(t, "down", c.take(), []string{
		"route -q -n delete -inet 10.144.0.0/16 -interface utun4",
		"route -q -n delete -inet6 fd77:6768::/64 -interface utun4",
		"rm -f /var/run/wireguard/utun4.sock",
		"rm -f /var/run/wireguard/wgh0.name",
	})
}

// TestDarwinUpIPv6Disabled: an IPv6 address that can't be set leaves the
// interface IPv4 only, and Up still succeeds.
func TestDarwinUpIPv6Disabled(t *testing.T) {
	d, c := freshDarwin()
	base := c.answer
	c.answer = func(line string, n int) (string, error) {
		if strings.Contains(line, "inet6") {
			return "", errFake
		}
		return base(line, n)
	}
	if err := d.Up(testIfc6); err != nil {
		t.Fatalf("Up failed because of IPv6: %v", err)
	}
	if d.IPv6Off("wgh0") == nil {
		t.Error("IPv6Off is nil")
	}
	c.take()
	if err := d.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	for _, line := range c.take() {
		if strings.Contains(line, "inet6") {
			t.Errorf("IPv6 exit step on an IPv4-only interface: %s", line)
		}
	}
}

func TestDarwinExitIPv6(t *testing.T) {
	d, c := freshDarwin6()
	d.Local = func() []netip.Prefix {
		return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("2001:db8:1::/64")}
	}
	if err := d.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	c.take()
	hosts := []netip.Addr{
		netip.MustParseAddr("203.0.113.9"),        // coordinator
		netip.MustParseAddr("2001:db8:77::9"),     // a peer over IPv6
		netip.MustParseAddr("2001:db8:1::20"),     // on this LAN
		netip.MustParseAddr("fd77:6768::a90:3"),   // inside the mesh
		netip.MustParseAddr("fe80::1234"),         // link-local
		netip.MustParseAddr("2001:db8:77::9%en0"), // same peer with a zone
	}
	if err := d.SetBypass("wgh0", hosts); err != nil {
		t.Fatal(err)
	}
	if err := d.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	expect(t, "exit on", c.take(), []string{
		"route -n get default",
		"route -n get -inet6 default",
		"route -q -n add -inet -host 203.0.113.9 -gateway 192.168.1.1",
		"route -q -n add -inet6 -host 2001:db8:77::9 -gateway fe80::1%en0",
		"route -q -n add -inet 0.0.0.0/1 -interface utun4",
		"route -q -n add -inet 128.0.0.0/1 -interface utun4",
		"route -q -n add -inet6 ::/1 -interface utun4",
		"route -q -n add -inet6 8000::/1 -interface utun4",
	})
	if err := d.SetExit("wgh0", false); err != nil {
		t.Fatal(err)
	}
	expect(t, "exit off", c.take(), []string{
		"route -q -n delete -inet 0.0.0.0/1 -interface utun4",
		"route -q -n delete -inet 128.0.0.0/1 -interface utun4",
		"route -q -n delete -inet6 ::/1 -interface utun4",
		"route -q -n delete -inet6 8000::/1 -interface utun4",
		"route -q -n delete -inet -host 203.0.113.9 -gateway 192.168.1.1",
		"route -q -n delete -inet6 -host 2001:db8:77::9 -gateway fe80::1%en0",
	})
}

// TestDarwinExitNoIPv6Gateway: with no IPv6 default route there is no IPv6
// internet to send through the exit node, so only IPv4 goes there.
func TestDarwinExitNoIPv6Gateway(t *testing.T) {
	d, c := freshDarwin()
	base := c.answer
	c.answer = func(line string, n int) (string, error) {
		if line == "route -n get -inet6 default" {
			return "", fakeErr("route: writing to routing socket: not in table")
		}
		return base(line, n)
	}
	if err := d.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	if err := d.SetBypass("wgh0", []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8:77::9")}); err != nil {
		t.Fatal(err)
	}
	c.take()
	if err := d.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	expect(t, "exit on", c.take(), []string{
		"route -n get default",
		"route -n get -inet6 default",
		"route -q -n add -inet -host 203.0.113.9 -gateway 192.168.1.1",
		"route -q -n add -inet 0.0.0.0/1 -interface utun4",
		"route -q -n add -inet 128.0.0.0/1 -interface utun4",
	})
	if err := d.Down("wgh0"); err != nil {
		t.Fatal(err)
	}
	for _, line := range c.take() {
		if strings.Contains(line, "::/1") {
			t.Errorf("IPv6 half removed that was never added: %s", line)
		}
	}
}

func TestDarwinDefaultGateway6(t *testing.T) {
	d, c := freshDarwin6()
	if err := d.Up(testIfc6); err != nil {
		t.Fatal(err)
	}
	if got := d.defaultGateway6("utun4"); strings.Join(got, " ") != "-gateway fe80::1%en0" {
		t.Fatalf("gateway = %v", got)
	}
	c.answer = func(string, int) (string, error) { return "  interface: ppp0\n", nil }
	if got := d.defaultGateway6("utun4"); strings.Join(got, " ") != "-interface ppp0" {
		t.Fatalf("interface route = %v", got)
	}
	c.answer = func(string, int) (string, error) { return "    gateway: fd77:6768::a90:1\n  interface: utun4\n", nil }
	if got := d.defaultGateway6("utun4"); got != nil {
		t.Fatalf("default route through the tunnel itself accepted: %v", got)
	}
}
