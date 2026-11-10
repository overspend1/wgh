package agent

import (
	"context"
	"net/netip"
	"strings"

	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/meshdns"
	"github.com/overspend1/wgh/internal/wgctl"
)

// What Status.DNS says.
const (
	DNSOn        = "on (resolved)"
	DNSHostsOnly = "hosts file only"
	DNSOff       = "off"
)

// dnsState is the built-in DNS server and its resolver setup. It is guarded
// by Agent.dnsMu, not Agent.mu, because starting it runs commands.
type dnsState struct {
	srv        *meshdns.Server
	cancel     context.CancelFunc
	done       chan struct{}
	configured bool
	failed     bool // gave up: names come from the hosts file only
}

func (a *Agent) dnsRun() wgctl.Runner {
	if a.o.DNSRun != nil {
		return a.o.DNSRun
	}
	return wgctl.ExecRunner
}

// dnsRecords turns the hosts entries of a netmap into DNS records.
func dnsRecords(hosts []HostEntry) map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	for _, h := range hosts {
		if ip, err := netip.ParseAddr(h.Address); err == nil {
			out[h.Name] = append(out[h.Name], ip)
		}
	}
	return out
}

// syncDNS starts the server on the first netmap, restarts it when the domain
// changes and feeds it the names of every netmap after that.
func (a *Agent) syncDNS(domain string, hosts []HostEntry) {
	if !a.o.DNS {
		return
	}
	if domain == "" {
		domain = mesh.DefaultDomain
	}
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	if a.dns.failed {
		return
	}
	if a.dns.srv != nil && a.dns.srv.Domain() != strings.ToLower(strings.Trim(domain, ".")) {
		a.stopDNSLocked()
	}
	if a.dns.srv == nil && !a.startDNSLocked(domain, dnsRecords(hosts)) {
		a.dns.failed = true
		return
	}
	a.dns.srv.SetRecords(dnsRecords(hosts))
}

func (a *Agent) startDNSLocked(domain string, records map[string][]netip.Addr) bool {
	a.mu.Lock()
	ifName, self := a.st.Interface, a.st.Address
	a.mu.Unlock()
	addr := a.o.DNSAddr
	if !addr.IsValid() {
		ip, err := netip.ParseAddr(self)
		if err != nil {
			a.o.Logf("dns: bad mesh address %q; names come from the hosts file only", self)
			return false
		}
		addr = netip.AddrPortFrom(ip, 53)
	}
	srv := meshdns.New(domain)
	srv.SetRecords(records)

	if a.o.DryRun {
		a.o.Logf("[dry-run] dns: would answer *.%s on %s (UDP and TCP)", srv.Domain(), addr)
		say := func(_ []byte, name string, args ...string) ([]byte, error) {
			a.o.Logf("[dry-run] dns: would run %s %s", name, strings.Join(args, " "))
			return nil, nil
		}
		_ = meshdns.Configure(say, ifName, addr.Addr(), srv.Domain())
		a.dns.srv = srv
		a.setDNSOn(true)
		return true
	}

	run := a.dnsRun()
	available := meshdns.Available
	if a.o.DNSAvailable != nil {
		available = a.o.DNSAvailable
	}
	if !available(run) {
		a.o.Logf("dns: systemd-resolved is not running or resolvectl is missing; names come from the hosts file only")
		return false
	}
	bound, err := srv.Listen(addr)
	if err != nil {
		a.o.Logf("dns: listen on %s: %v; names come from the hosts file only", addr, err)
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, bound)
	}()
	if err := meshdns.Configure(run, ifName, bound.Addr(), srv.Domain()); err != nil {
		cancel()
		<-done
		a.o.Logf("dns: %v; names come from the hosts file only", err)
		return false
	}
	a.dns = dnsState{srv: srv, cancel: cancel, done: done, configured: true}
	a.setDNSOn(true)
	a.o.Logf("dns: answering *.%s on %s through systemd-resolved", srv.Domain(), bound)
	return true
}

func (a *Agent) stopDNSLocked() {
	if a.dns.configured {
		a.mu.Lock()
		ifName := a.st.Interface
		a.mu.Unlock()
		if err := meshdns.Unconfigure(a.dnsRun(), ifName); err != nil {
			a.o.Logf("dns: %v", err)
		}
	}
	if a.dns.cancel != nil {
		a.dns.cancel()
		<-a.dns.done
	}
	a.dns = dnsState{failed: a.dns.failed}
	a.setDNSOn(false)
}

// stopDNS undoes the resolver setup and stops the server.
func (a *Agent) stopDNS() {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	a.stopDNSLocked()
}

func (a *Agent) setDNSOn(on bool) {
	a.mu.Lock()
	a.dnsOn = on
	a.mu.Unlock()
}

// dnsModeLocked is Status.DNS.
func (a *Agent) dnsModeLocked() string {
	switch {
	case !a.o.DNS:
		return DNSOff
	case a.dnsOn:
		return DNSOn
	case a.o.HostsPath != "":
		return DNSHostsOnly
	}
	return DNSOff
}

// dnsAddr is where the server listens, for tests.
func (a *Agent) dnsAddr() netip.AddrPort {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	if a.dns.srv == nil {
		return netip.AddrPort{}
	}
	return a.dns.srv.Addr()
}
