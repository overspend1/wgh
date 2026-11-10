package wgctl

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// FilterRule lets new connections from Src to Dst through. An empty Src or
// Dst matches any address.
type FilterRule struct {
	Src string `json:"src,omitempty"` // prefix, e.g. 10.144.0.2/32
	Dst string `json:"dst,omitempty"`
}

func (r FilterRule) String() string {
	return orAny(r.Src) + " -> " + orAny(r.Dst)
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

// FilterScope says which traffic on an interface a filter covers.
type FilterScope int

const (
	// FilterInbound covers everything arriving on the interface: for this
	// machine, and forwarded on to its LAN or the internet. Devices use it.
	FilterInbound FilterScope = iota
	// FilterRelayed covers only traffic that comes in on the interface and
	// goes back out through it, from one peer to another. The relay uses it.
	FilterRelayed
)

func (s FilterScope) String() string {
	if s == FilterRelayed {
		return "relayed"
	}
	return "inbound"
}

// Filter is an optional Backend feature: a firewall on the interface that
// lets new connections through only when a rule matches. Replies to allowed
// connections (conntrack ESTABLISHED and RELATED) always pass. A backend
// without it simply doesn't enforce the access policy locally.
type Filter interface {
	// SetFilter makes the filter on interface name exactly rules. nil rules
	// remove the filter, so everything passes; an empty non-nil list lets
	// no new connection through.
	SetFilter(name string, scope FilterScope, rules []FilterRule) error
}

// ValidFilterRules checks that every address in rules is a plain prefix.
func ValidFilterRules(rules []FilterRule) error {
	for _, r := range rules {
		for _, a := range []string{r.Src, r.Dst} {
			if a == "" {
				continue
			}
			if p, err := netip.ParsePrefix(a); err != nil || p.String() != a || p != p.Masked() {
				return fmt.Errorf("filter rule %s: %q is not a prefix", r, a)
			}
		}
	}
	return nil
}

// FilterChain is the iptables chain holding the filter of interface name.
func FilterChain(name string) string { return "WGH-" + name }

type filterState struct {
	scope FilterScope
	rules []FilterRule
}

// hooks are where the chain is jumped to from, per scope.
func filterHooks(name string, scope FilterScope) [][]string {
	if scope == FilterRelayed {
		return [][]string{{"FORWARD", "-i", name, "-o", name}}
	}
	return [][]string{{"INPUT", "-i", name}, {"FORWARD", "-i", name}}
}

// FilterRestore renders the iptables-restore input that replaces the chain
// of interface name with rules, in one atomic step: there is no moment when
// the chain is empty and lets everything through.
func FilterRestore(name string, rules []FilterRule) []byte {
	chain := FilterChain(name)
	c := "-m comment --comment wgh"
	var b strings.Builder
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n", chain)
	fmt.Fprintf(&b, "-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT %s\n", chain, c)
	for _, r := range rules {
		fmt.Fprintf(&b, "-A %s", chain)
		if r.Src != "" {
			fmt.Fprintf(&b, " -s %s", r.Src)
		}
		if r.Dst != "" {
			fmt.Fprintf(&b, " -d %s", r.Dst)
		}
		fmt.Fprintf(&b, " -j ACCEPT %s\n", c)
	}
	fmt.Fprintf(&b, "-A %s -j DROP %s\nCOMMIT\n", chain, c)
	return []byte(b.String())
}

// SetFilter implements Filter with an iptables chain per interface, WGH-<name>,
// tagged with the comment "wgh". The chain's content is replaced in full
// with iptables-restore --noflush on every change; the jumps into it sit at
// the top of INPUT and FORWARD (or only FORWARD, for the relay).
func (l *Linux) SetFilter(name string, scope FilterScope, rules []FilterRule) error {
	if err := ValidFilterRules(rules); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := l.filters[name]
	if rules == nil {
		if cur != nil {
			l.filterOff(name, cur.scope)
			delete(l.filters, name)
		}
		return nil
	}
	if cur != nil && cur.scope == scope && slices.Equal(cur.rules, rules) {
		return nil
	}
	if _, err := l.Run(FilterRestore(name, rules), "iptables-restore", "-w", "--noflush"); err != nil {
		return err
	}
	if cur != nil && cur.scope == scope {
		cur.rules = append([]FilterRule{}, rules...)
		return nil // the jumps are in place
	}
	if cur != nil {
		l.unhook(name, cur.scope)
	}
	chain := FilterChain(name)
	for _, h := range filterHooks(name, scope) {
		rule := append(append([]string(nil), h[1:]...), "-j", chain, "-m", "comment", "--comment", "wgh")
		// -C first, so a jump left by an earlier run isn't added twice.
		if _, err := l.Run(nil, "iptables", append([]string{"-w", "-C", h[0]}, rule...)...); err == nil {
			continue
		}
		if err := l.run(append([]string{"iptables", "-w", "-I", h[0], "1"}, rule...)...); err != nil {
			return err
		}
	}
	if l.filters == nil {
		l.filters = map[string]*filterState{}
	}
	l.filters[name] = &filterState{scope: scope, rules: append([]FilterRule{}, rules...)}
	return nil
}

func (l *Linux) unhook(name string, scope FilterScope) {
	chain := FilterChain(name)
	for _, h := range filterHooks(name, scope) {
		args := append([]string{"iptables", "-w", "-D", h[0]}, h[1:]...)
		_ = l.run(append(args, "-j", chain, "-m", "comment", "--comment", "wgh")...)
	}
}

func (l *Linux) filterOff(name string, scope FilterScope) {
	l.unhook(name, scope)
	chain := FilterChain(name)
	_ = l.run("iptables", "-w", "-F", chain)
	_ = l.run("iptables", "-w", "-X", chain)
}

// SetFilter implements Filter by recording the rules.
func (f *Fake) SetFilter(name string, scope FilterScope, rules []FilterRule) error {
	if err := ValidFilterRules(rules); err != nil {
		return err
	}
	f.mu.Lock()
	changed := f.filterOn != (rules != nil) || f.filterScope != scope || !slices.Equal(f.filter, rules)
	f.filterOn, f.filterScope = rules != nil, scope
	f.filter = append([]FilterRule(nil), rules...)
	f.mu.Unlock()
	if !changed {
		return nil
	}
	switch {
	case rules == nil:
		f.logf("[dry-run] %s: no access filter", name)
	case len(rules) == 0:
		f.logf("[dry-run] %s: %s filter: no new connections allowed", name, scope)
	default:
		parts := make([]string, len(rules))
		for i, r := range rules {
			parts[i] = r.String()
		}
		f.logf("[dry-run] %s: %s filter: allow new connections %s", name, scope, strings.Join(parts, ", "))
	}
	return nil
}
