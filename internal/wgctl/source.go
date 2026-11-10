package wgctl

import (
	"slices"
	"strconv"
)

// SourceTable holds the default route for traffic the relay sends on to a
// relayed exit node.
const SourceTable = RouteTable + 1

// sourcePriority is the policy rule priority for those sources.
const sourcePriority = SourceTable

// SourceRouter is implemented by backends that can send the internet
// traffic of some mesh addresses back into the interface, so WireGuard
// passes it to the peer holding 0.0.0.0/0. The relay uses it to reach an
// exit node that a device has no direct path to.
type SourceRouter interface {
	// SetSourceRoutes makes traffic arriving on the interface from these
	// prefixes leave through it again. Empty turns it off.
	SetSourceRoutes(name string, sources []string) error
}

// SetSourceRoutes implements SourceRouter with one policy rule per source,
// all looking up a table whose default route is the interface. Local
// addresses and the main table's more specific mesh routes still win,
// because the local table is consulted first and WireGuard picks the peer
// by the most specific AllowedIPs.
func (l *Linux) SetSourceRoutes(name string, sources []string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if slices.Equal(sources, l.sources) && l.sources != nil {
		return nil
	}
	if l.sources == nil {
		l.sourcesLeftover()
	} else {
		l.sourcesOff()
	}
	l.sources = []string{}
	if len(sources) == 0 {
		return nil
	}
	table, prio := strconv.Itoa(SourceTable), strconv.Itoa(sourcePriority)
	if err := l.run("ip", "route", "replace", "default", "dev", name, "table", table); err != nil {
		return err
	}
	for _, src := range sources {
		if err := l.run("ip", "rule", "add", "from", src, "iif", name, "lookup", table, "priority", prio); err != nil {
			l.sourcesOff()
			return err
		}
	}
	l.sources = append([]string{}, sources...)
	return nil
}

// sourcesOff removes the rules and the table this backend added. Callers
// hold l.mu.
func (l *Linux) sourcesOff() {
	table, prio := strconv.Itoa(SourceTable), strconv.Itoa(sourcePriority)
	for _, src := range l.sources {
		_ = l.run("ip", "rule", "del", "from", src, "lookup", table, "priority", prio)
	}
	if len(l.sources) > 0 {
		_ = l.run("ip", "route", "flush", "table", table)
	}
}

// sourcesLeftover clears rules a previous run may have left behind after a
// crash, before the first SetSourceRoutes. Callers hold l.mu.
func (l *Linux) sourcesLeftover() {
	prio := strconv.Itoa(sourcePriority)
	for i := 0; i < 64; i++ {
		if out, err := l.Run(nil, "ip", "rule", "del", "priority", prio); err != nil || len(out) > 0 {
			break
		}
	}
	_ = l.run("ip", "route", "flush", "table", strconv.Itoa(SourceTable))
}

// SetSourceRoutes implements SourceRouter by recording the sources.
func (f *Fake) SetSourceRoutes(name string, sources []string) error {
	f.mu.Lock()
	was := len(f.sources) > 0
	f.sources = append([]string(nil), sources...)
	f.mu.Unlock()
	if len(sources) > 0 || was {
		f.logf("[dry-run] relay internet traffic from %v on to the relayed exit node", sources)
	}
	return nil
}
