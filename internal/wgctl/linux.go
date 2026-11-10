package wgctl

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner runs a command, feeding it stdin, and returns its output.
type Runner func(stdin []byte, name string, args ...string) ([]byte, error)

// ExecRunner runs real commands.
func ExecRunner(stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.Bytes(), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return out.Bytes(), nil
}

// Linux configures the interface with ip, wg, iptables and sysctl. It uses
// the kernel WireGuard module and falls back to wireguard-go when the kernel
// has no WireGuard support. Everything it does needs root.
type Linux struct {
	Run Runner

	mu      sync.Mutex
	routes  map[string]bool
	exit    bool
	forward string // subnet forwarded, if any
	natIf   string
	filters map[string]*filterState // by interface, see SetFilter
	sources []string                // see SetSourceRoutes

	// IPv6, see linux6.go.
	v6       map[string]netip.Prefix // interfaces with their IPv6 address set
	v6off    map[string]error        // why an interface asked for IPv6 has none
	exit6    bool                    // the IPv6 half of SetExit is in place
	forward6 string                  // IPv6 range forwarded, if any
}

// NewLinux returns a Linux backend that runs real commands.
func NewLinux() *Linux { return &Linux{Run: ExecRunner} }

func (l *Linux) run(args ...string) error {
	_, err := l.Run(nil, args[0], args[1:]...)
	return err
}

// Up implements Backend.
func (l *Linux) Up(ifc Interface) error {
	if _, err := l.Run(nil, "ip", "link", "show", "dev", ifc.Name); err != nil {
		if err := l.run("ip", "link", "add", "dev", ifc.Name, "type", "wireguard"); err != nil {
			// No kernel module: try the userspace implementation, as wg-quick does.
			if _, lerr := exec.LookPath("wireguard-go"); lerr != nil {
				return fmt.Errorf("%w (and wireguard-go is not installed)", err)
			}
			if err := l.run("wireguard-go", ifc.Name); err != nil {
				return err
			}
		}
	}
	if err := l.run("ip", "address", "replace", ifc.Address.String(), "dev", ifc.Name); err != nil {
		return err
	}
	mtu := ifc.MTU
	if mtu == 0 {
		mtu = 1280 // safe through most tunnels and mobile networks
	}
	if err := l.run("ip", "link", "set", "dev", ifc.Name, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	l.up6(ifc) // never fails Up: without IPv6 the interface is IPv4 only
	return nil
}

// Config renders the wg setconf file for ifc and peers.
func Config(ifc Interface, peers []Peer) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\n", ifc.PrivateKey)
	if ifc.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", ifc.ListenPort)
	}
	fmt.Fprintf(&b, "FwMark = 0x%x\n", FwMark)
	for _, p := range SortedPeers(peers) {
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", p.PublicKey)
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return []byte(b.String())
}

// SetPeers implements Backend. The config, which holds the private key, is
// passed on stdin so it never lands on disk.
func (l *Linux) SetPeers(ifc Interface, peers []Peer) error {
	_, err := l.Run(Config(ifc, peers), "wg", "syncconf", ifc.Name, "/dev/stdin")
	return err
}

// Stats implements Backend by parsing 'wg show <name> dump'.
func (l *Linux) Stats(name string) ([]PeerStat, error) {
	out, err := l.Run(nil, "wg", "show", name, "dump")
	if err != nil {
		return nil, err
	}
	return ParseDump(out)
}

// ParseDump parses the output of 'wg show <iface> dump'.
func ParseDump(out []byte) ([]PeerStat, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var stats []PeerStat
	for i, line := range lines {
		if i == 0 || line == "" { // the first line describes the interface
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			return nil, fmt.Errorf("unexpected wg dump line %d: %q", i+1, line)
		}
		s := PeerStat{PublicKey: f[0]}
		if f[2] != "(none)" {
			s.Endpoint = f[2]
		}
		if hs, _ := strconv.ParseInt(f[4], 10, 64); hs > 0 {
			s.LastHandshake = time.Unix(hs, 0)
		}
		s.RxBytes, _ = strconv.ParseInt(f[5], 10, 64)
		s.TxBytes, _ = strconv.ParseInt(f[6], 10, 64)
		stats = append(stats, s)
	}
	return stats, nil
}

// SetRoutes implements Backend. The routes get a high metric so a network
// you are directly plugged into keeps winning over the same range via mesh.
func (l *Linux) SetRoutes(name string, routes []string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.routes == nil {
		l.routes = map[string]bool{}
	}
	want := map[string]bool{}
	for _, r := range routes {
		want[r] = true
	}
	var errs []error
	for r := range l.routes {
		if !want[r] {
			if err := l.run(routeCmd("del", r, name)...); err != nil {
				errs = append(errs, err)
			}
			delete(l.routes, r)
		}
	}
	sorted := make([]string, 0, len(want))
	for r := range want {
		sorted = append(sorted, r)
	}
	sort.Strings(sorted)
	for _, r := range sorted {
		if l.routes[r] {
			continue
		}
		if isIPv6(r) && !l.v6[name].IsValid() {
			continue // no IPv6 on the interface: added if it gets some
		}
		if err := l.run(routeCmd("replace", r, name)...); err != nil {
			errs = append(errs, err)
			continue
		}
		l.routes[r] = true
	}
	return errors.Join(errs...)
}

// SetExit implements Backend with the same policy routing wg-quick uses for
// a full tunnel: everything not marked as WireGuard's own traffic goes to a
// table whose default route is the interface.
//
// With IPv6 on the interface the same table and rules are set up for IPv6
// too. If that fails the whole exit node is turned off again rather than
// leaving IPv6 traffic to go out past it.
func (l *Linux) SetExit(name string, on bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	six := l.v6[name].IsValid()
	if on == l.exit && (!on || l.exit6 == six) {
		return nil
	}
	if !on {
		l.exitOff(name, l.exit6)
		l.exit = false
		return nil
	}
	if !l.exit {
		for _, args := range exitRules("-4", name) {
			if err := l.run(args...); err != nil {
				l.exitOff(name, false)
				return err
			}
		}
		l.exit = true
	}
	if six && !l.exit6 {
		for _, args := range exitRules("-6", name) {
			if err := l.run(args...); err != nil {
				l.exitOff(name, true)
				l.exit = false
				return fmt.Errorf("IPv6 exit routing, so the exit node stays off: %w", err)
			}
		}
		l.exit6 = true
	}
	return nil
}

// exitRules are the policy routing commands of SetExit for one family, "-4"
// or "-6".
func exitRules(fam, name string) [][]string {
	mark, table := fmt.Sprintf("0x%x", FwMark), strconv.Itoa(RouteTable)
	return [][]string{
		{"ip", fam, "route", "replace", "default", "dev", name, "table", table},
		{"ip", fam, "rule", "add", "not", "fwmark", mark, "table", table, "priority", "5767"},
		{"ip", fam, "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", "5766"},
	}
}

// exitOff undoes SetExit, the IPv6 half too when six is set.
func (l *Linux) exitOff(name string, six bool) {
	table := strconv.Itoa(RouteTable)
	fams := []string{"-4"}
	if six {
		fams = append(fams, "-6")
	}
	for _, fam := range fams {
		_ = l.run("ip", fam, "rule", "del", "priority", "5767")
		_ = l.run("ip", fam, "rule", "del", "priority", "5766")
		_ = l.run("ip", fam, "route", "flush", "table", table)
	}
	l.exit6 = false
}

// SetForward implements Backend: IPv4 forwarding plus a MASQUERADE rule for
// mesh traffic leaving through any other interface.
func (l *Linux) SetForward(name, subnet string, on bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if on && l.forward == subnet {
		return nil
	}
	if !on && l.forward == "" {
		return nil
	}
	if l.forward != "" {
		l.forwardOff(name)
	}
	if !on {
		return nil
	}
	if err := l.run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	for _, args := range forwardRules("-A", name, subnet) {
		if err := l.run(args...); err != nil {
			l.forward = subnet
			l.forwardOff(name)
			return err
		}
	}
	l.forward = subnet
	return nil
}

func forwardRules(op, name, subnet string) [][]string {
	return forwardRulesFor("iptables", op, name, subnet)
}

// forwardRulesFor are the forwarding and NAT rules, for iptables or
// ip6tables.
func forwardRulesFor(ipt, op, name, subnet string) [][]string {
	c := []string{"-m", "comment", "--comment", "wgh"}
	return [][]string{
		append([]string{ipt, "-w", op, "FORWARD", "-i", name, "-j", "ACCEPT"}, c...),
		append([]string{ipt, "-w", op, "FORWARD", "-o", name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, c...),
		append([]string{ipt, "-w", "-t", "nat", op, "POSTROUTING", "-s", subnet, "!", "-o", name, "-j", "MASQUERADE"}, c...),
	}
}

func (l *Linux) forwardOff(name string) {
	for _, args := range forwardRules("-D", name, l.forward) {
		_ = l.run(args...)
	}
	l.forward = ""
}

// Down implements Backend.
func (l *Linux) Down(name string) error {
	l.mu.Lock()
	if l.exit {
		l.exitOff(name, l.exit6)
		l.exit = false
	}
	if l.forward != "" {
		l.forwardOff(name)
	}
	if l.forward6 != "" {
		l.forward6Off(name)
	}
	if f := l.filters[name]; f != nil {
		l.filterOff(name, f)
		delete(l.filters, name)
	}
	if l.sources != nil {
		l.sourcesOff()
		l.sources = nil
	}
	l.routes = nil
	delete(l.v6, name)
	delete(l.v6off, name)
	l.mu.Unlock()
	if _, err := l.Run(nil, "ip", "link", "show", "dev", name); err != nil {
		return nil // already gone
	}
	return l.run("ip", "link", "del", "dev", name)
}
