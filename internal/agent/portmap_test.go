package agent

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/overspend1/wgh/internal/portmap"
)

type fakeMapper struct {
	release chan struct{} // Map waits for it
	now     func() time.Time
	ext     string
	fail    error

	mu     sync.Mutex
	maps   int
	unmaps []portmap.Mapping
}

func (f *fakeMapper) Map(ctx context.Context, port int, life time.Duration) (portmap.Mapping, error) {
	select {
	case <-f.release:
	case <-ctx.Done():
		return portmap.Mapping{}, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maps++
	if f.fail != nil {
		return portmap.Mapping{}, f.fail
	}
	return portmap.Mapping{Protocol: portmap.ProtoUPnP, External: netip.MustParseAddrPort(f.ext), Expires: f.now().Add(life)}, nil
}

func (f *fakeMapper) Unmap(ctx context.Context, m portmap.Mapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmaps = append(f.unmaps, m)
	return nil
}

func (f *fakeMapper) counts() (maps, unmaps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maps, len(f.unmaps)
}

func (r *rig) mappedOf(name string) string {
	for _, d := range r.srv.Status().Devices {
		if d.Name == name {
			return d.Mapped
		}
	}
	return ""
}

func TestPortMapHeartbeat(t *testing.T) {
	r := newRig(t)
	fm := &fakeMapper{release: make(chan struct{}), now: r.clk.Now, ext: "203.0.113.5:41820"}
	logs := &logLines{}
	r.opts = func(name string, o *Options) {
		if name == "laptop" {
			// Only a prompt heartbeat can carry the mapping within the test.
			o.PortMap, o.PortMapper, o.Heartbeat, o.Logf = true, fm, time.Hour, logs.logf
		}
	}
	a := r.join("laptop", "192.168.1.10", nil, false)
	b := r.join("pve1", "192.168.1.20", nil, false)
	eventually(t, "first heartbeat", func() bool {
		for _, d := range r.srv.Status().Devices {
			if d.Name == "laptop" && d.Online {
				return true
			}
		}
		return false
	})
	if s := a.a.Status().PortMap; s != "searching" {
		t.Errorf("status before mapping = %q", s)
	}
	close(fm.release)
	eventually(t, "mapped endpoint at the coordinator", func() bool { return r.mappedOf("laptop") == fm.ext })
	if s := a.a.Status().PortMap; s != "UPnP 203.0.113.5:41820" {
		t.Errorf("status = %q", s)
	}
	if n := logs.count("portmap: UPnP forwards 203.0.113.5:41820"); n != 1 {
		t.Errorf("%d success lines", n)
	}
	// pve1 learns it as a candidate for laptop.
	eventually(t, "pve1 sees the mapped endpoint", func() bool {
		b.a.mu.Lock()
		defer b.a.mu.Unlock()
		if b.a.nm == nil {
			return false
		}
		for _, n := range b.a.nm.Peers {
			if n.Name == "laptop" && slices.Contains(n.Endpoints, fm.ext) {
				return true
			}
		}
		return false
	})
	if r.mappedOf("pve1") != "" {
		t.Error("pve1 has a mapping it never made")
	}

	// Stopping the agent removes the mapping.
	a.a.Stop()
	err := <-a.done
	a.done <- err
	if maps, unmaps := fm.counts(); maps != 1 || unmaps != 1 {
		t.Fatalf("maps %d, unmaps %d", maps, unmaps)
	}
	if s := a.a.Status().PortMap; s != "off" {
		t.Errorf("status after stop = %q", s)
	}
}

func TestPortMapFailureAndDryRun(t *testing.T) {
	r := newRig(t)
	release := make(chan struct{})
	close(release)
	failing := &fakeMapper{release: release, now: r.clk.Now,
		fail: fmt.Errorf("%w: UPnP gateway's external address is 192.168.0.2", portmap.ErrDoubleNAT)}
	dry := &fakeMapper{release: release, now: r.clk.Now, ext: "203.0.113.5:41820"}
	logs := map[string]*logLines{"laptop": {}, "dry": {}, "off": {}}
	r.opts = func(name string, o *Options) {
		o.Logf = logs[name].logf
		switch name {
		case "laptop":
			o.PortMap, o.PortMapper, o.PortMapRetry = true, failing, 5*time.Millisecond
		case "dry":
			o.PortMap, o.PortMapper, o.DryRun = true, dry, true
		case "off":
			o.PortMapper = dry
		}
	}
	a := r.join("laptop", "192.168.1.10", nil, false)
	d := r.join("dry", "192.168.1.11", nil, false)
	off := r.join("off", "192.168.1.12", nil, false)
	eventually(t, "several tries", func() bool { n, _ := failing.counts(); return n >= 3 })
	if s := a.a.Status().PortMap; s != "double NAT, mapping not useful" {
		t.Errorf("status = %q", s)
	}
	if n := logs["laptop"].count("portmap:"); n != 1 {
		t.Errorf("%d portmap log lines for repeated failures, want 1", n)
	}
	if r.mappedOf("laptop") != "" {
		t.Error("failed mapping reached the coordinator")
	}
	if n := logs["dry"].count("[dry-run] portmap: would"); n != 1 {
		t.Errorf("dry run logged %d portmap lines", n)
	}
	if n, _ := dry.counts(); n != 0 {
		t.Errorf("mapper called %d times in a dry run or with port mapping off", n)
	}
	if s := d.a.Status().PortMap; s != "off (dry run)" {
		t.Errorf("dry-run status = %q", s)
	}
	if s := off.a.Status().PortMap; s != "off" {
		t.Errorf("status with port mapping off = %q", s)
	}
}
