package wgctl

import (
	"bytes"
	"errors"
	"fmt"
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
	return l.run("ip", "link", "set", "dev", ifc.Name, "mtu", strconv.Itoa(mtu), "up")
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
			if err := l.run("ip", "route", "del", r, "dev", name, "metric", "1000"); err != nil {
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
		if err := l.run("ip", "route", "replace", r, "dev", name, "metric", "1000"); err != nil {
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
func (l *Linux) SetExit(name string, on bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if on == l.exit {
		return nil
	}
	mark, table := fmt.Sprintf("0x%x", FwMark), strconv.Itoa(RouteTable)
	if on {
		for _, args := range [][]string{
			{"ip", "-4", "route", "replace", "default", "dev", name, "table", table},
			{"ip", "-4", "rule", "add", "not", "fwmark", mark, "table", table, "priority", "5767"},
			{"ip", "-4", "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", "5766"},
		} {
			if err := l.run(args...); err != nil {
				l.exitOff(name)
				return err
			}
		}
		l.exit = true
		return nil
	}
	l.exitOff(name)
	l.exit = false
	return nil
}

func (l *Linux) exitOff(name string) {
	table := strconv.Itoa(RouteTable)
	_ = l.run("ip", "-4", "rule", "del", "priority", "5767")
	_ = l.run("ip", "-4", "rule", "del", "priority", "5766")
	_ = l.run("ip", "-4", "route", "flush", "table", table)
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
	c := []string{"-m", "comment", "--comment", "wgh"}
	return [][]string{
		append([]string{"iptables", "-w", op, "FORWARD", "-i", name, "-j", "ACCEPT"}, c...),
		append([]string{"iptables", "-w", op, "FORWARD", "-o", name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, c...),
		append([]string{"iptables", "-w", "-t", "nat", op, "POSTROUTING", "-s", subnet, "!", "-o", name, "-j", "MASQUERADE"}, c...),
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
		l.exitOff(name)
		l.exit = false
	}
	if l.forward != "" {
		l.forwardOff(name)
	}
	l.routes = nil
	l.mu.Unlock()
	if _, err := l.Run(nil, "ip", "link", "show", "dev", name); err != nil {
		return nil // already gone
	}
	return l.run("ip", "link", "del", "dev", name)
}
