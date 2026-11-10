package wgctl

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// cmdLog is a fake Runner: it records every command and answers from a
// script keyed by the command line. A missing key succeeds with no output.
type cmdLog struct {
	ran    []string
	stdin  map[string][]byte
	answer func(line string, n int) (string, error) // n: times line ran before
	count  map[string]int
}

func (c *cmdLog) run(stdin []byte, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	c.ran = append(c.ran, line)
	if c.stdin == nil {
		c.stdin, c.count = map[string][]byte{}, map[string]int{}
	}
	if stdin != nil {
		c.stdin[line] = stdin
	}
	n := c.count[line]
	c.count[line]++
	if c.answer == nil {
		return nil, nil
	}
	out, err := c.answer(line, n)
	return []byte(out), err
}

func (c *cmdLog) take() []string { r := c.ran; c.ran = nil; return r }

func expect(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s commands:\n%s\n\nwant:\n%s", what, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

var testIfc = Interface{Name: "wgh0", Address: netip.MustParsePrefix("10.144.0.5/16"), ListenPort: 41820, PrivateKey: "SECRETKEY"}

// freshDarwin answers like a Mac where wgh0 has never been up: no name file
// until wireguard-go has run, then utun4.
func freshDarwin() (*Darwin, *cmdLog) {
	c := &cmdLog{}
	started := false
	c.answer = func(line string, _ int) (string, error) {
		switch line {
		case "env -u LOG_LEVEL WG_TUN_NAME_FILE=/var/run/wireguard/wgh0.name wireguard-go utun":
			started = true
		case "cat /var/run/wireguard/wgh0.name":
			if !started {
				return "", errFake
			}
			return "utun4\n", nil
		case "test -S /var/run/wireguard/utun4.sock":
			if !started {
				return "", errFake
			}
		case "route -n get default":
			return routeGetDefault, nil
		}
		return "", nil
	}
	return &Darwin{Run: c.run}, c
}

const routeGetDefault = `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`

func TestDarwinUpFresh(t *testing.T) {
	d, c := freshDarwin()
	if err := d.Up(testIfc); err != nil {
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
	})
	// Up again in the same process (a key rotation): the mapping is used,
	// nothing is started and the mesh route is not added twice.
	if err := d.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	expect(t, "second up", c.take(), []string{
		"test -S /var/run/wireguard/utun4.sock",
		"ifconfig utun4 inet 10.144.0.5/16 10.144.0.5 alias",
		"ifconfig utun4 mtu 1280",
		"ifconfig utun4 up",
	})
}

func TestDarwinUpReuse(t *testing.T) {
	c := &cmdLog{answer: func(line string, _ int) (string, error) {
		if line == "cat /var/run/wireguard/wgh0.name" {
			return "utun7\n", nil
		}
		return "", nil
	}}
	d := &Darwin{Run: c.run}
	ifc := testIfc
	ifc.MTU = 1380
	if err := d.Up(ifc); err != nil {
		t.Fatal(err)
	}
	expect(t, "reuse", c.take(), []string{
		"cat /var/run/wireguard/wgh0.name",
		"test -S /var/run/wireguard/utun7.sock",
		"ifconfig utun7 inet 10.144.0.5/16 10.144.0.5 alias",
		"ifconfig utun7 mtu 1380",
		"ifconfig utun7 up",
		"route -q -n delete -inet 10.144.0.0/16 -interface utun7",
		"route -q -n add -inet 10.144.0.0/16 -interface utun7",
	})
}

func TestDarwinUpStaleNameFile(t *testing.T) {
	// A name file whose socket is gone: wireguard-go is started again.
	c := &cmdLog{answer: func(line string, _ int) (string, error) {
		switch line {
		case "cat /var/run/wireguard/wgh0.name":
			return "utun2", nil
		case "test -S /var/run/wireguard/utun2.sock":
			return "", errFake
		}
		return "", nil
	}}
	d := &Darwin{Run: c.run}
	if err := d.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	if got := c.take(); len(got) < 4 || !strings.Contains(got[3], "wireguard-go utun") {
		t.Fatalf("stale name file did not restart wireguard-go:\n%s", strings.Join(got, "\n"))
	}
}

func TestDarwinUpBadNameFile(t *testing.T) {
	c := &cmdLog{answer: func(line string, _ int) (string, error) {
		if strings.HasPrefix(line, "cat ") {
			return "en0; rm -rf /", nil
		}
		return "", nil
	}}
	d := &Darwin{Run: c.run}
	if err := d.Up(testIfc); err == nil || !strings.Contains(err.Error(), "not a utun interface") {
		t.Fatalf("Up with a bad name file: %v", err)
	}
}

func TestDarwinSetPeersKeyOnStdin(t *testing.T) {
	d, c := freshDarwin()
	if err := d.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	c.take()
	peers := []Peer{{PublicKey: "PEER", Endpoint: "198.51.100.2:41820", AllowedIPs: []string{"10.144.0.3/32"}, Keepalive: 25}}
	if err := d.SetPeers(testIfc, peers); err != nil {
		t.Fatal(err)
	}
	ran := c.take()
	expect(t, "set peers", ran, []string{"wg syncconf utun4 /dev/stdin"})
	for _, line := range ran {
		if strings.Contains(line, "SECRETKEY") {
			t.Fatalf("private key on the command line: %s", line)
		}
	}
	if got := string(c.stdin["wg syncconf utun4 /dev/stdin"]); got != string(Config(testIfc, peers)) ||
		!strings.Contains(got, "PrivateKey = SECRETKEY") {
		t.Fatalf("stdin:\n%s", got)
	}

	c.answer = func(line string, _ int) (string, error) {
		return "PRIV\tPUB\t41820\toff\nPEER\t(none)\t198.51.100.2:41820\t10.144.0.3/32\t1700000000\t10\t20\t25\n", nil
	}
	stats, err := d.Stats("wgh0")
	if err != nil || len(stats) != 1 || stats[0].RxBytes != 10 {
		t.Fatalf("stats = %+v, %v", stats, err)
	}
	expect(t, "stats", c.take(), []string{"wg show utun4 dump"})
}

func TestDarwinSetRoutes(t *testing.T) {
	d, c := freshDarwin()
	if err := d.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	c.take()
	if err := d.SetRoutes("wgh0", []string{"192.168.50.0/24", "fd00:1::/64"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetRoutes("wgh0", []string{"192.168.50.0/24", "192.168.60.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetRoutes("wgh0", []string{"192.168.50.0/24", "192.168.60.0/24"}); err != nil {
		t.Fatal(err)
	}
	expect(t, "routes", c.take(), []string{
		"route -q -n add -inet 192.168.50.0/24 -interface utun4",
		"route -q -n add -inet6 fd00:1::/64 -interface utun4",
		"route -q -n delete -inet6 fd00:1::/64 -interface utun4",
		"route -q -n add -inet 192.168.60.0/24 -interface utun4",
	})
	// A route that fails to add is retried next time.
	c.answer = func(line string, n int) (string, error) {
		if line == "route -q -n add -inet 10.9.0.0/16 -interface utun4" && n == 0 {
			return "", errFake
		}
		return "", nil
	}
	if err := d.SetRoutes("wgh0", []string{"10.9.0.0/16"}); err == nil {
		t.Fatal("failed route add not reported")
	}
	if err := d.SetRoutes("wgh0", []string{"10.9.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	expect(t, "retry", c.take(), []string{
		"route -q -n delete -inet 192.168.50.0/24 -interface utun4",
		"route -q -n delete -inet 192.168.60.0/24 -interface utun4",
		"route -q -n add -inet 10.9.0.0/16 -interface utun4",
		"route -q -n add -inet 10.9.0.0/16 -interface utun4",
	})
}

func TestDarwinExitBypass(t *testing.T) {
	d, c := freshDarwin()
	d.Local = func() []netip.Prefix {
		return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("127.0.0.0/8")}
	}
	if err := d.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	c.take()
	hosts := []netip.Addr{
		netip.MustParseAddr("203.0.113.9"),    // coordinator
		netip.MustParseAddr("198.51.100.2"),   // a peer
		netip.MustParseAddr("192.168.1.20"),   // on this LAN: the LAN route wins anyway
		netip.MustParseAddr("10.20.0.7"),      // private but not local: kept
		netip.MustParseAddr("10.144.0.3"),     // inside the mesh
		netip.MustParseAddr("127.0.0.1"),      // loopback
		netip.MustParseAddr("2001:db8::1"),    // IPv6 stays outside the exit node
		netip.MustParseAddr("::ffff:1.2.3.4"), // mapped IPv4
		netip.MustParseAddr("203.0.113.9"),    // duplicate
	}
	// Before the exit node is on, the list is only kept.
	if err := d.SetBypass("wgh0", hosts); err != nil {
		t.Fatal(err)
	}
	expect(t, "bypass while off", c.take(), nil)

	if err := d.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	if err := d.SetExit("wgh0", true); err != nil { // no-op
		t.Fatal(err)
	}
	expect(t, "exit on", c.take(), []string{
		"route -n get default",
		"route -q -n add -inet -host 1.2.3.4 -gateway 192.168.1.1",
		"route -q -n add -inet -host 10.20.0.7 -gateway 192.168.1.1",
		"route -q -n add -inet -host 198.51.100.2 -gateway 192.168.1.1",
		"route -q -n add -inet -host 203.0.113.9 -gateway 192.168.1.1",
		"route -q -n add -inet 0.0.0.0/1 -interface utun4",
		"route -q -n add -inet 128.0.0.0/1 -interface utun4",
	})

	// A peer moves: its old address is released and the new one added.
	if err := d.SetBypass("wgh0", []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("198.51.100.77")}); err != nil {
		t.Fatal(err)
	}
	expect(t, "bypass change", c.take(), []string{
		"route -q -n delete -inet -host 1.2.3.4 -gateway 192.168.1.1",
		"route -q -n delete -inet -host 10.20.0.7 -gateway 192.168.1.1",
		"route -q -n delete -inet -host 198.51.100.2 -gateway 192.168.1.1",
		"route -q -n add -inet -host 198.51.100.77 -gateway 192.168.1.1",
	})

	if err := d.SetExit("wgh0", false); err != nil {
		t.Fatal(err)
	}
	if err := d.SetExit("wgh0", false); err != nil { // no-op
		t.Fatal(err)
	}
	expect(t, "exit off", c.take(), []string{
		"route -q -n delete -inet 0.0.0.0/1 -interface utun4",
		"route -q -n delete -inet 128.0.0.0/1 -interface utun4",
		"route -q -n delete -inet -host 198.51.100.77 -gateway 192.168.1.1",
		"route -q -n delete -inet -host 203.0.113.9 -gateway 192.168.1.1",
	})
}

func TestDarwinExitFailureRollsBack(t *testing.T) {
	d, c := freshDarwin()
	if err := d.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	if err := d.SetBypass("wgh0", []netip.Addr{netip.MustParseAddr("203.0.113.9")}); err != nil {
		t.Fatal(err)
	}
	c.take()
	base := c.answer
	c.answer = func(line string, n int) (string, error) {
		if line == "route -q -n add -inet 128.0.0.0/1 -interface utun4" {
			return "", errFake
		}
		return base(line, n)
	}
	if err := d.SetExit("wgh0", true); err == nil {
		t.Fatal("failure not reported")
	}
	expect(t, "rollback", c.take(), []string{
		"route -n get default",
		"route -q -n add -inet -host 203.0.113.9 -gateway 192.168.1.1",
		"route -q -n add -inet 0.0.0.0/1 -interface utun4",
		"route -q -n add -inet 128.0.0.0/1 -interface utun4",
		"route -q -n delete -inet 0.0.0.0/1 -interface utun4",
		"route -q -n delete -inet 128.0.0.0/1 -interface utun4",
		"route -q -n delete -inet -host 203.0.113.9 -gateway 192.168.1.1",
	})
}

func TestDarwinDefaultGateway(t *testing.T) {
	// A link with no gateway, such as some PPP or tethered connections.
	gw, ifc := ParseRouteGet([]byte("   route to: default\ndestination: default\n  interface: ppp0\n      flags: <UP,DONE,STATIC>\n"))
	if gw.IsValid() || ifc != "ppp0" {
		t.Fatalf("gateway %v, interface %q", gw, ifc)
	}
	d, c := freshDarwin()
	if err := d.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	if got, err := d.defaultGateway("utun4"); err != nil || strings.Join(got, " ") != "-gateway 192.168.1.1" {
		t.Fatalf("gateway = %v, %v", got, err)
	}
	c.answer = func(string, int) (string, error) { return "  interface: ppp0\n", nil }
	if got, err := d.defaultGateway("utun4"); err != nil || strings.Join(got, " ") != "-interface ppp0" {
		t.Fatalf("interface route = %v, %v", got, err)
	}
	c.answer = func(string, int) (string, error) { return "    gateway: 10.144.0.1\n  interface: utun4\n", nil }
	if _, err := d.defaultGateway("utun4"); err == nil {
		t.Fatal("default route through the tunnel itself accepted")
	}
	c.answer = func(string, int) (string, error) { return "", errFake }
	if err := d.SetExit("wgh0", true); err == nil || !strings.Contains(err.Error(), "no default route") {
		t.Fatalf("no default route: %v", err)
	}
}

func TestDarwinDown(t *testing.T) {
	d, c := freshDarwin()
	if err := d.Up(testIfc); err != nil {
		t.Fatal(err)
	}
	if err := d.SetRoutes("wgh0", []string{"192.168.50.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetBypass("wgh0", []netip.Addr{netip.MustParseAddr("203.0.113.9")}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetExit("wgh0", true); err != nil {
		t.Fatal(err)
	}
	c.take()
	if err := d.Down("wgh0"); err != nil {
		t.Fatal(err)
	}
	expect(t, "down", c.take(), []string{
		"route -q -n delete -inet 0.0.0.0/1 -interface utun4",
		"route -q -n delete -inet 128.0.0.0/1 -interface utun4",
		"route -q -n delete -inet -host 203.0.113.9 -gateway 192.168.1.1",
		"route -q -n delete -inet 192.168.50.0/24 -interface utun4",
		"route -q -n delete -inet 10.144.0.0/16 -interface utun4",
		"rm -f /var/run/wireguard/utun4.sock",
		"rm -f /var/run/wireguard/wgh0.name",
	})

	// Down with nothing up does nothing.
	d2 := &Darwin{Run: (&cmdLog{answer: func(string, int) (string, error) { return "", errFake }}).run}
	if err := d2.Down("wgh0"); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinForward(t *testing.T) {
	d, _ := freshDarwin()
	if err := d.SetForward("wgh0", "10.144.0.0/16", true); !errors.Is(err, ErrNoForward) ||
		err.Error() != "sharing routes, exit node and relay need Linux" {
		t.Fatalf("SetForward on = %v", err)
	}
	if err := d.SetForward("wgh0", "10.144.0.0/16", false); err != nil {
		t.Fatalf("SetForward off = %v", err)
	}
	if !errors.Is(CanForward(d), ErrNoForward) {
		t.Error("CanForward(Darwin) is not ErrNoForward")
	}
	if CanForward(&Linux{}) != nil || CanForward(NewFake(nil, nil, "")) != nil {
		t.Error("Linux and Fake should forward")
	}
	var _ Bypasser = d
	var _ Bypasser = NewFake(nil, nil, "")
}

func TestCheckMessages(t *testing.T) {
	if got := ErrUnsupportedOS.Error(); got != "wgh up runs on Linux and macOS; on this system use the WireGuard app with 'wgh admin phone'" {
		t.Errorf("unsupported OS message = %q", got)
	}
	var u Unsupported
	if err := u.Up(testIfc); !errors.Is(err, ErrUnsupportedOS) {
		t.Errorf("Unsupported.Up = %v", err)
	}
	all := func(string) (string, error) { return "/usr/bin/x", nil }
	if err := checkDarwin(0, all); err != nil {
		t.Errorf("all tools there: %v", err)
	}
	if err := checkDarwin(501, all); err == nil || !strings.Contains(err.Error(), "sudo wgh up") {
		t.Errorf("not root: %v", err)
	}
	noWGGo := func(tool string) (string, error) {
		if tool == "wireguard-go" {
			return "", errFake
		}
		return "/usr/bin/" + tool, nil
	}
	if err := checkDarwin(0, noWGGo); err == nil || !strings.Contains(err.Error(), "brew install wireguard-tools") ||
		!strings.Contains(err.Error(), "wireguard-go") {
		t.Errorf("missing wireguard-go: %v", err)
	}
}
