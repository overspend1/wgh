package wgctl

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// IPv6 inside the mesh, on Linux. Up adds the interface's IPv6 address
// when it is given one; the other methods add the IPv6 half of what they do
// only for an interface that has it. A host with IPv6 turned off keeps
// working over IPv4: Up records why (see IPv6Off) and carries on.

// isIPv6 reports whether the prefix or address s is IPv6.
func isIPv6(s string) bool { return strings.Contains(s, ":") }

// routeCmd is the ip command that adds ("replace") or removes ("del") a
// route through the interface. IPv4 routes keep their original form.
func routeCmd(op, r, name string) []string {
	if isIPv6(r) {
		return []string{"ip", "-6", "route", op, r, "dev", name, "metric", "1000"}
	}
	return []string{"ip", "route", op, r, "dev", name, "metric", "1000"}
}

// up6 gives the interface its IPv6 address, or records why it can't.
func (l *Linux) up6(ifc Interface) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.v6 == nil {
		l.v6, l.v6off = map[string]netip.Prefix{}, map[string]error{}
	}
	a := ifc.Address6
	if !a.IsValid() {
		delete(l.v6, ifc.Name)
		delete(l.v6off, ifc.Name)
		return
	}
	off := func(err error) {
		delete(l.v6, ifc.Name)
		l.v6off[ifc.Name] = err
	}
	if !a.Addr().Is6() || a.Addr().Is4In6() || a.Addr().Zone() != "" {
		off(fmt.Errorf("%s is not an IPv6 interface address", a))
		return
	}
	if _, err := l.Run(nil, "test", "-d", "/proc/sys/net/ipv6"); err != nil {
		off(errors.New("the kernel has no IPv6 (/proc/sys/net/ipv6 is missing)"))
		return
	}
	if err := l.run("ip", "-6", "address", "replace", a.String(), "dev", ifc.Name); err != nil {
		off(fmt.Errorf("IPv6 looks disabled on this host: %w", err))
		return
	}
	l.v6[ifc.Name] = a
	delete(l.v6off, ifc.Name)
}

// IPv6Off implements IPv6Reporter.
func (l *Linux) IPv6Off(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.v6off[name]
}

// SetForward6 implements Forwarder6: IPv6 forwarding plus a MASQUERADE rule
// for the mesh's IPv6 range leaving through any other interface, so an exit
// node takes mesh IPv6 out to the internet from its own address, as
// Tailscale does for its ULA range. Nothing happens when the interface has
// no IPv6.
func (l *Linux) SetForward6(name, subnet6 string, on bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !on || !l.v6[name].IsValid() {
		if l.forward6 != "" {
			l.forward6Off(name)
		}
		return nil
	}
	if p, err := netip.ParsePrefix(subnet6); err != nil || !p.Addr().Is6() || p != p.Masked() {
		return fmt.Errorf("bad IPv6 mesh range %q", subnet6)
	}
	if l.forward6 == subnet6 {
		return nil
	}
	if l.forward6 != "" {
		l.forward6Off(name)
	}
	if err := l.run("sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return err
	}
	for _, args := range forwardRulesFor("ip6tables", "-A", name, subnet6) {
		if err := l.run(args...); err != nil {
			l.forward6 = subnet6
			l.forward6Off(name)
			return err
		}
	}
	l.forward6 = subnet6
	return nil
}

func (l *Linux) forward6Off(name string) {
	for _, args := range forwardRulesFor("ip6tables", "-D", name, l.forward6) {
		_ = l.run(args...)
	}
	l.forward6 = ""
}
