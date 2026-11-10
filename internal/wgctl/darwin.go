package wgctl

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ErrNoForward is what SetForward returns where this machine can't forward
// and NAT mesh traffic for other devices.
var ErrNoForward = errors.New("sharing routes, exit node and relay need Linux")

// Bypasser is implemented by backends that send the exit node's traffic
// through ordinary routes instead of policy routing. SetBypass names the
// hosts that must keep going out the normal way while an exit node is on:
// the coordinator and the peers' endpoints. Without that, the tunnel's own
// packets would be routed into the tunnel.
type Bypasser interface {
	SetBypass(name string, hosts []netip.Addr) error
}

// CanForward reports, without changing anything, whether b can forward and
// NAT mesh traffic (nil) or not (ErrNoForward), so an agent knows before it
// offers routes or an exit node to the mesh.
func CanForward(b Backend) error {
	if c, ok := b.(interface{ CanForward() error }); ok {
		return c.CanForward()
	}
	return nil
}

// wgRunDir is where wireguard-go keeps its control sockets on macOS, and
// where wg-quick keeps the logical-name-to-utun files.
const wgRunDir = "/var/run/wireguard"

var (
	utunRE    = regexp.MustCompile(`^utun[0-9]+$`)
	ifaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)
)

// Darwin configures the interface on macOS the way wg-quick does there:
// wireguard-go makes a utunN device (macOS picks N), ifconfig sets its
// address and route adds the routes. The logical name (wgh0) is mapped to
// the real utunN through /var/run/wireguard/<name>.name. Everything goes
// through Run, so the command sequences are testable anywhere.
type Darwin struct {
	Run Runner
	// Local lists the networks this machine is directly on. Their addresses
	// never need a bypass route: the connected route is more specific than
	// the exit node's halves of the internet. Nil means none.
	Local func() []netip.Prefix

	mu     sync.Mutex
	real   map[string]string       // logical name -> utunN
	addr   map[string]netip.Prefix // logical name -> interface address
	subnet map[string]string       // logical name -> mesh route added
	routes map[string]bool
	exit   bool
	gw     []string // "-gateway", "192.168.1.1" or "-interface", "en0"
	want   []netip.Addr
	added  map[netip.Addr][]string // bypass host -> gateway it was added via
}

// NewDarwin returns a macOS backend that runs real commands.
func NewDarwin() *Darwin { return &Darwin{Run: ExecRunner, Local: localPrefixes} }

// CanForward reports that macOS can't forward for the mesh (pf NAT is not
// set up by wgh).
func (d *Darwin) CanForward() error { return ErrNoForward }

func (d *Darwin) run(args ...string) error {
	_, err := d.Run(nil, args[0], args[1:]...)
	return err
}

func nameFile(name string) string { return wgRunDir + "/" + name + ".name" }
func sockFile(real string) string { return wgRunDir + "/" + real + ".sock" }

// readName reads the utunN that wireguard-go reported for name.
func (d *Darwin) readName(name string) (string, error) {
	out, err := d.Run(nil, "cat", nameFile(name))
	if err != nil {
		return "", err
	}
	real := strings.TrimSpace(string(out))
	if !utunRE.MatchString(real) {
		return "", fmt.Errorf("%s holds %q, not a utun interface", nameFile(name), real)
	}
	return real, nil
}

// running reports whether wireguard-go is serving real.
func (d *Darwin) running(real string) bool {
	_, err := d.Run(nil, "test", "-S", sockFile(real))
	return err == nil
}

// dev returns the utunN for a logical name.
func (d *Darwin) dev(name string) (string, error) {
	d.mu.Lock()
	real, ok := d.real[name]
	d.mu.Unlock()
	if ok {
		return real, nil
	}
	if !ifaceName.MatchString(name) {
		return "", fmt.Errorf("bad interface name %q", name)
	}
	real, err := d.readName(name)
	if err != nil {
		return "", fmt.Errorf("%s is not up", name)
	}
	return real, nil
}

func family(p string) string {
	if strings.Contains(p, ":") {
		return "-inet6"
	}
	return "-inet"
}

// Up implements Backend. A wireguard-go that is already running for this
// name, from this process or an earlier one, is reused.
func (d *Darwin) Up(ifc Interface) error {
	if !ifaceName.MatchString(ifc.Name) {
		return fmt.Errorf("bad interface name %q", ifc.Name)
	}
	if !ifc.Address.Addr().Is4() {
		return fmt.Errorf("interface address %s is not IPv4", ifc.Address)
	}
	d.mu.Lock()
	mapped := d.real[ifc.Name]
	routed := d.subnet[ifc.Name]
	d.mu.Unlock()

	real, earlier := "", false
	if mapped != "" && d.running(mapped) {
		real = mapped
	} else if r, err := d.readName(ifc.Name); err == nil && d.running(r) {
		real, earlier, routed = r, true, ""
	} else {
		routed = ""
		if err := d.run("mkdir", "-p", wgRunDir); err != nil {
			return err
		}
		// wireguard-go daemonizes once the utun device and its socket exist
		// and writes the device's name to WG_TUN_NAME_FILE. LOG_LEVEL is
		// cleared because with it set the daemon keeps our output pipes open.
		if err := d.run("env", "-u", "LOG_LEVEL", "WG_TUN_NAME_FILE="+nameFile(ifc.Name), "wireguard-go", "utun"); err != nil {
			return err
		}
		r, err := d.readName(ifc.Name)
		if err != nil {
			return fmt.Errorf("wireguard-go started but its interface name is unknown: %w", err)
		}
		real = r
	}
	d.mu.Lock()
	if d.real == nil {
		d.real, d.addr, d.subnet = map[string]string{}, map[string]netip.Prefix{}, map[string]string{}
	}
	d.real[ifc.Name], d.addr[ifc.Name] = real, ifc.Address
	d.mu.Unlock()

	mtu := ifc.MTU
	if mtu == 0 {
		mtu = 1280 // safe through most tunnels and mobile networks
	}
	for _, args := range [][]string{
		{"ifconfig", real, "inet", ifc.Address.String(), ifc.Address.Addr().String(), "alias"},
		{"ifconfig", real, "mtu", strconv.Itoa(mtu)},
		{"ifconfig", real, "up"},
	} {
		if err := d.run(args...); err != nil {
			return err
		}
	}
	subnet := ifc.Address.Masked().String()
	if routed == subnet {
		return nil
	}
	if earlier {
		// An earlier wgh may have left this route on the reused device.
		_ = d.run("route", "-q", "-n", "delete", "-inet", subnet, "-interface", real)
	}
	if err := d.run("route", "-q", "-n", "add", "-inet", subnet, "-interface", real); err != nil {
		return err
	}
	d.mu.Lock()
	d.subnet[ifc.Name] = subnet
	d.mu.Unlock()
	return nil
}

// SetPeers implements Backend. The config, which holds the private key, is
// passed on stdin so it never lands on disk. wireguard-go on macOS accepts
// and ignores the FwMark line.
func (d *Darwin) SetPeers(ifc Interface, peers []Peer) error {
	real, err := d.dev(ifc.Name)
	if err != nil {
		return err
	}
	_, err = d.Run(Config(ifc, peers), "wg", "syncconf", real, "/dev/stdin")
	return err
}

// Stats implements Backend by parsing 'wg show utunN dump'.
func (d *Darwin) Stats(name string) ([]PeerStat, error) {
	real, err := d.dev(name)
	if err != nil {
		return nil, err
	}
	out, err := d.Run(nil, "wg", "show", real, "dump")
	if err != nil {
		return nil, err
	}
	return ParseDump(out)
}

// SetRoutes implements Backend.
func (d *Darwin) SetRoutes(name string, routes []string) error {
	real, err := d.dev(name)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.routes == nil {
		d.routes = map[string]bool{}
	}
	want := map[string]bool{}
	for _, r := range routes {
		want[r] = true
	}
	var errs []error
	for _, r := range sortedKeys(d.routes) {
		if !want[r] {
			if err := d.run("route", "-q", "-n", "delete", family(r), r, "-interface", real); err != nil {
				errs = append(errs, err)
			}
			delete(d.routes, r)
		}
	}
	for _, r := range sortedKeys(want) {
		if d.routes[r] {
			continue
		}
		if err := d.run("route", "-q", "-n", "add", family(r), r, "-interface", real); err != nil {
			errs = append(errs, err)
			continue
		}
		d.routes[r] = true
	}
	return errors.Join(errs...)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// exitHalves cover all of IPv4 while staying more specific than the
// default route, which is left alone, as wg-quick does.
var exitHalves = []string{"0.0.0.0/1", "128.0.0.0/1"}

// SetExit implements Backend. Before the two halves of the internet are
// pointed at the interface, each bypass host gets a host route via the
// original default gateway, so WireGuard and the coordinator keep working.
func (d *Darwin) SetExit(name string, on bool) error {
	real, err := d.dev(name)
	if err != nil {
		if !on {
			return nil
		}
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if on == d.exit {
		return nil
	}
	if !on {
		d.exitOff(real)
		return nil
	}
	gw, err := d.defaultGateway(real)
	if err != nil {
		return err
	}
	d.gw, d.added = gw, map[netip.Addr][]string{}
	_ = d.syncBypass(d.want) // a host that fails is retried by SetBypass
	for _, half := range exitHalves {
		if err := d.run("route", "-q", "-n", "add", "-inet", half, "-interface", real); err != nil {
			d.exitOff(real)
			return err
		}
	}
	d.exit = true
	return nil
}

func (d *Darwin) exitOff(real string) {
	for _, half := range exitHalves {
		_ = d.run("route", "-q", "-n", "delete", "-inet", half, "-interface", real)
	}
	_ = d.syncBypass(nil)
	d.exit, d.gw, d.added = false, nil, nil
}

// defaultGateway reads where the default route goes, as route arguments.
func (d *Darwin) defaultGateway(real string) ([]string, error) {
	out, err := d.Run(nil, "route", "-n", "get", "default")
	if err != nil {
		return nil, fmt.Errorf("no default route, so nothing for the exit node to replace: %w", err)
	}
	gw, ifc := ParseRouteGet(out)
	switch {
	case ifc == real:
		return nil, fmt.Errorf("the default route already goes through %s", real)
	case gw.Is4():
		return []string{"-gateway", gw.String()}, nil
	case ifc != "":
		return []string{"-interface", ifc}, nil
	}
	return nil, errors.New("the default route has no gateway or interface")
}

// ParseRouteGet reads the gateway and interface from 'route -n get' output.
func ParseRouteGet(out []byte) (gateway netip.Addr, iface string) {
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "gateway":
			if a, err := netip.ParseAddr(v); err == nil {
				gateway = a.Unmap()
			}
		case "interface":
			iface = v
		}
	}
	return gateway, iface
}

// SetBypass implements Bypasser. Only IPv4 hosts that are neither on a
// local network nor in the mesh get routes, and only while the exit node
// is on; the list is kept for when it turns on.
func (d *Darwin) SetBypass(name string, hosts []netip.Addr) error {
	d.mu.Lock()
	mesh := d.addr[name]
	d.mu.Unlock()
	var local []netip.Prefix
	if d.Local != nil {
		local = d.Local()
	}
	seen := map[netip.Addr]bool{}
	var want []netip.Addr
	for _, h := range hosts {
		h = h.Unmap()
		if !h.Is4() || !h.IsGlobalUnicast() || seen[h] || (mesh.IsValid() && mesh.Masked().Contains(h)) {
			continue
		}
		onLink := false
		for _, p := range local {
			if p.Contains(h) {
				onLink = true
			}
		}
		if onLink {
			continue
		}
		seen[h] = true
		want = append(want, h)
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Less(want[j]) })
	d.mu.Lock()
	defer d.mu.Unlock()
	d.want = want
	if !d.exit {
		return nil
	}
	return d.syncBypass(want)
}

// syncBypass makes the bypass host routes exactly want. Called with mu held.
func (d *Darwin) syncBypass(want []netip.Addr) error {
	keep := map[netip.Addr]bool{}
	for _, h := range want {
		keep[h] = true
	}
	var errs []error
	old := make([]netip.Addr, 0, len(d.added))
	for h := range d.added {
		old = append(old, h)
	}
	sort.Slice(old, func(i, j int) bool { return old[i].Less(old[j]) })
	for _, h := range old {
		if !keep[h] {
			args := append([]string{"route", "-q", "-n", "delete", "-inet", "-host", h.String()}, d.added[h]...)
			if err := d.run(args...); err != nil {
				errs = append(errs, err)
			}
			delete(d.added, h)
		}
	}
	if d.gw == nil {
		return errors.Join(errs...)
	}
	for _, h := range want {
		if _, ok := d.added[h]; ok {
			continue
		}
		args := append([]string{"route", "-q", "-n", "add", "-inet", "-host", h.String()}, d.gw...)
		if err := d.run(args...); err != nil {
			errs = append(errs, err)
			continue
		}
		d.added[h] = d.gw
	}
	return errors.Join(errs...)
}

// SetForward implements Backend: turning it on fails with ErrNoForward.
func (d *Darwin) SetForward(_, _ string, on bool) error {
	if on {
		return ErrNoForward
	}
	return nil
}

// Down implements Backend. Removing the control socket makes wireguard-go
// close the utun device and exit, which also drops the routes through it.
func (d *Darwin) Down(name string) error {
	real, err := d.dev(name)
	if err != nil {
		return nil // already gone
	}
	d.mu.Lock()
	if d.exit {
		d.exitOff(real)
	}
	var errs []error
	for _, r := range sortedKeys(d.routes) {
		if err := d.run("route", "-q", "-n", "delete", family(r), r, "-interface", real); err != nil {
			errs = append(errs, err)
		}
	}
	d.routes = nil
	if s := d.subnet[name]; s != "" {
		_ = d.run("route", "-q", "-n", "delete", "-inet", s, "-interface", real)
	}
	delete(d.real, name)
	delete(d.addr, name)
	delete(d.subnet, name)
	d.mu.Unlock()
	if err := d.run("rm", "-f", sockFile(real)); err != nil {
		errs = append(errs, err)
	}
	if err := d.run("rm", "-f", nameFile(name)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// localPrefixes lists the networks of this machine's interfaces.
func localPrefixes() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}
