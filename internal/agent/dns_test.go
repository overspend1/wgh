package agent

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/overspend1/wgh/internal/wgctl"
)

// cmdLog is a fake wgctl.Runner that records commands.
type cmdLog struct {
	mu   sync.Mutex
	cmds []string
}

func (c *cmdLog) run(_ []byte, name string, args ...string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmds = append(c.cmds, strings.Join(append([]string{name}, args...), " "))
	return nil, nil
}

func (c *cmdLog) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.cmds...)
}

type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) logf(format string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, a...))
	l.mu.Unlock()
}

func (l *logLines) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// dnsLookup asks a DNS server over UDP and returns the rcode and addresses.
func dnsLookup(t *testing.T, server netip.AddrPort, name string, qtype uint16) (int, []netip.Addr) {
	t.Helper()
	q := []byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	c, err := net.Dial("udp", server.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1500)
	n, err := c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	b = b[:n]
	if n < len(q) || b[0] != 0xab || b[1] != 0xcd {
		t.Fatalf("bad response %x", b)
	}
	rcode := int(b[3] & 0xF)
	ancount := int(binary.BigEndian.Uint16(b[6:]))
	off := len(q) // the question is echoed as sent
	var ips []netip.Addr
	for i := 0; i < ancount; i++ {
		for off < len(b) && b[off] != 0 && b[off]&0xC0 != 0xC0 {
			off += 1 + int(b[off])
		}
		if off < len(b) && b[off] == 0 {
			off++
		} else {
			off += 2
		}
		if off+10 > len(b) {
			t.Fatalf("short answer %x", b)
		}
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		data := b[off+10 : off+10+rdlen]
		if ip, ok := netip.AddrFromSlice(data); ok {
			ips = append(ips, ip)
		}
		off += 10 + rdlen
	}
	return rcode, ips
}

func TestMeshDNS(t *testing.T) {
	r := newRig(t)
	runs := map[string]*cmdLog{"laptop": {}, "pve1": {}}
	r.opts = func(name string, o *Options) {
		o.DNS = true
		o.DNSRun = runs[name].run
		o.DNSAvailable = func(wgctl.Runner) bool { return true }
		o.DNSAddr = netip.MustParseAddrPort("127.0.0.1:0")
	}
	a := r.join("laptop", "192.168.1.10", nil, false)
	b := r.join("pve1", "192.168.1.20", nil, false)

	var srv netip.AddrPort
	eventually(t, "laptop's DNS server", func() bool { srv = a.a.dnsAddr(); return srv.IsValid() })
	eventually(t, "pve1 in laptop's DNS", func() bool {
		rc, ips := dnsLookup(t, srv, "pve1.wgh", 1)
		return rc == 0 && len(ips) == 1 && ips[0].String() == "10.144.0.3"
	})
	if rc, ips := dnsLookup(t, srv, "LAPTOP.wgh", 1); rc != 0 || len(ips) != 1 || ips[0].String() != "10.144.0.2" {
		t.Errorf("self: rcode %d %v", rc, ips)
	}
	if rc, ips := dnsLookup(t, srv, "relay.wgh", 1); rc != 0 || len(ips) != 1 || ips[0].String() != r.srv.Status().Relay.Address {
		t.Errorf("relay: rcode %d %v", rc, ips)
	}
	if rc, ips := dnsLookup(t, srv, "pve1.wgh", 28); rc != 0 || len(ips) != 0 {
		t.Errorf("AAAA: rcode %d %v", rc, ips)
	}
	if rc, _ := dnsLookup(t, srv, "example.com", 1); rc != 5 {
		t.Errorf("outside the mesh: rcode %d, want REFUSED", rc)
	}
	want := []string{"resolvectl dns wgh0 127.0.0.1", "resolvectl domain wgh0 wgh", "resolvectl default-route wgh0 false"}
	if got := runs["laptop"].all(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("resolver commands:\n%s", strings.Join(got, "\n"))
	}
	if st := a.a.Status(); st.DNS != DNSOn {
		t.Errorf("status DNS = %q", st.DNS)
	}
	// The hosts file is still written.
	eventually(t, "hosts file", func() bool {
		h, _ := os.ReadFile(a.hosts)
		return strings.Contains(string(h), "10.144.0.3\tpve1 pve1.wgh")
	})

	// A removed peer leaves the DNS too. Wait until pve1 has configured
	// its own resolver, so there is something for it to revert.
	eventually(t, "pve1's resolver", func() bool { return len(runs["pve1"].all()) == 3 })
	if err := r.srv.Remove("pve1"); err != nil {
		t.Fatal(err)
	}
	err := <-b.done
	b.done <- err
	if got := runs["pve1"].all(); len(got) == 0 || got[len(got)-1] != "resolvectl revert wgh0" {
		t.Errorf("pve1 did not revert the resolver: %v", got)
	}
	eventually(t, "pve1 gone from laptop's DNS", func() bool {
		rc, _ := dnsLookup(t, srv, "pve1.wgh", 1)
		return rc == 3
	})

	// Stopping the agent reverts the resolver and closes the server.
	a.a.Stop()
	err = <-a.done
	a.done <- err
	if got := runs["laptop"].all(); len(got) != 4 || got[3] != "resolvectl revert wgh0" {
		t.Errorf("laptop commands after stop: %v", got)
	}
	if c, err := net.Dial("tcp", srv.String()); err == nil {
		c.Close()
		t.Error("DNS server still listening after the agent stopped")
	}
	if a.a.Status().DNS != DNSHostsOnly {
		t.Errorf("status DNS after stop = %q", a.a.Status().DNS)
	}
}

func TestMeshDNSFallback(t *testing.T) {
	r := newRig(t)
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	taken := busy.LocalAddr().(*net.UDPAddr).AddrPort()

	runs := map[string]*cmdLog{"nores": {}, "busy": {}, "off": {}}
	logs := map[string]*logLines{"nores": {}, "busy": {}, "off": {}}
	r.opts = func(name string, o *Options) {
		o.DNS = name != "off"
		o.DNSRun = runs[name].run
		o.Logf = logs[name].logf
		o.DNSAvailable = func(wgctl.Runner) bool { return name != "nores" }
		o.DNSAddr = netip.MustParseAddrPort("127.0.0.1:0")
		if name == "busy" {
			o.DNSAddr = taken
		}
	}
	devs := map[string]*dev{
		"nores": r.join("nores", "192.168.1.10", nil, false),
		"busy":  r.join("busy", "192.168.1.20", nil, false),
		"off":   r.join("off", "192.168.1.30", nil, false),
	}
	for name, d := range devs {
		eventually(t, name+" sees its peers", func() bool { return len(d.a.Status().Peers) == 3 })
		time.Sleep(100 * time.Millisecond) // several reconciles
		want := DNSHostsOnly
		if name == "off" {
			want = DNSOff
		}
		if st := d.a.Status(); st.DNS != want {
			t.Errorf("%s: status DNS = %q, want %q", name, st.DNS, want)
		}
		if d.a.dnsAddr().IsValid() {
			t.Errorf("%s: DNS server running", name)
		}
		if got := runs[name].all(); len(got) != 0 {
			t.Errorf("%s ran %v", name, got)
		}
		wantLogs := 1
		if name == "off" {
			wantLogs = 0
		}
		if n := logs[name].count("dns:"); n != wantLogs {
			t.Errorf("%s logged about DNS %d times, want %d", name, n, wantLogs)
		}
		h, _ := os.ReadFile(d.hosts)
		if !strings.Contains(string(h), "relay.wgh") {
			t.Errorf("%s: hosts file not written:\n%s", name, h)
		}
	}
}

func TestMeshDNSDryRun(t *testing.T) {
	r := newRig(t)
	runs := &cmdLog{}
	logs := &logLines{}
	r.opts = func(_ string, o *Options) {
		o.DNS, o.DryRun, o.DNSRun, o.Logf = true, true, runs.run, logs.logf
		o.DNSAvailable = func(wgctl.Runner) bool { t.Error("dry run checked for resolved"); return false }
	}
	d := r.join("laptop", "192.168.1.10", nil, false)
	eventually(t, "dry-run DNS", func() bool { return d.a.Status().DNS == DNSOn })
	if d.a.dnsAddr().IsValid() {
		t.Error("dry run listens")
	}
	if got := runs.all(); len(got) != 0 {
		t.Errorf("dry run ran %v", got)
	}
	for _, want := range []string{"would answer *.wgh on 10.144.0.2:53", "would run resolvectl dns wgh0 10.144.0.2",
		"would run resolvectl domain wgh0 wgh"} {
		if logs.count(want) != 1 {
			t.Errorf("dry run did not print %q", want)
		}
	}
}

func TestMeshDNSResolverFile(t *testing.T) {
	r := newRig(t)
	dirs := map[string]string{"laptop": filepath.Join(t.TempDir(), "resolver")}
	r.opts = func(name string, o *Options) {
		o.DNS = true
		o.ResolverDir = dirs[name]
		o.DNSAddr = netip.MustParseAddrPort("127.0.0.1:0")
		o.DNSRun = func([]byte, string, ...string) ([]byte, error) {
			t.Error("resolvectl must not run in resolver-file mode")
			return nil, nil
		}
	}
	a := r.join("laptop", "192.168.1.10", nil, false)
	file := filepath.Join(dirs["laptop"], "wgh")
	eventually(t, "resolver file", func() bool {
		b, _ := os.ReadFile(file)
		return strings.Contains(string(b), "nameserver 127.0.0.1")
	})
	a.a.Stop()
	err := <-a.done
	a.done <- err
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("resolver file left behind")
	}
}
