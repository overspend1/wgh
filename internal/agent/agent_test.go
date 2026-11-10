package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/overspend1/wgh/internal/coord"
	"github.com/overspend1/wgh/internal/keys"
	"github.com/overspend1/wgh/internal/wgctl"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func init() {
	wgctl.SetPublicKeyFunc(func(priv string) string {
		pub, err := keys.Public(priv)
		if err != nil {
			return "bad"
		}
		return pub
	})
}

type rig struct {
	t      *testing.T
	clk    *clock
	net    *wgctl.Network
	srv    *coord.Server
	http   *httptest.Server
	relay  *wgctl.Fake
	dir    string
	cancel context.CancelFunc
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, clk: &clock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}, net: wgctl.NewNetwork(), dir: t.TempDir()}
	r.net.Now = r.clk.Now
	var h http.Handler
	r.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { h.ServeHTTP(w, req) }))
	t.Cleanup(r.http.Close)
	r.relay = wgctl.NewFake(nil, r.net, "relay.example:51820")
	srv, err := coord.New(coord.Options{Dir: filepath.Join(r.dir, "coord"), URL: r.http.URL, Endpoint: "relay.example",
		PlainHTTP: true, Exit: true, Backend: r.relay, Now: r.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	h = srv.APIHandler()
	return r
}

type dev struct {
	a     *Agent
	fake  *wgctl.Fake
	path  string
	hosts string
	done  chan error
	pub   string
}

func (r *rig) join(name, ip string, routes []string, exit bool) *dev {
	r.t.Helper()
	tok, err := r.srv.NewToken(time.Hour, false, false)
	if err != nil {
		r.t.Fatal(err)
	}
	path := filepath.Join(r.dir, name, "agent.json")
	st, err := Join(context.Background(), path, JoinOptions{Token: tok, Name: name, Routes: routes, Exit: exit})
	if err != nil {
		r.t.Fatal(err)
	}
	hosts := filepath.Join(r.dir, name, "hosts")
	os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o644)
	addr := netip.MustParseAddr(ip)
	fake := wgctl.NewFake(nil, r.net, ip+":41820")
	a, err := New(Options{StatePath: path, Backend: fake, HostsPath: hosts, Now: r.clk.Now,
		PollWait: time.Second, Heartbeat: 30 * time.Millisecond, Tick: 20 * time.Millisecond,
		LocalAddrs: func() []netip.Addr { return []netip.Addr{addr} }, NoSocket: true})
	if err != nil {
		r.t.Fatal(err)
	}
	d := &dev{a: a, fake: fake, path: path, hosts: hosts, done: make(chan error, 1), pub: st.PublicKey}
	ctx, cancel := context.WithCancel(context.Background())
	r.t.Cleanup(func() { cancel(); <-d.done })
	go func() { d.done <- a.Run(ctx) }()
	return d
}

func (r *rig) sweep() { r.srv.Sweep() }

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func peerStatus(d *dev, name string) PeerStatus {
	for _, p := range d.a.Status().Peers {
		if p.Name == name {
			return p
		}
	}
	return PeerStatus{}
}

func TestMeshEndToEnd(t *testing.T) {
	r := newRig(t)
	a := r.join("laptop", "192.168.1.10", nil, false)
	b := r.join("pve1", "192.168.1.20", []string{"192.168.50.0/24"}, true)

	// Both devices find each other directly over the LAN.
	eventually(t, "direct path laptop->pve1", func() bool { return peerStatus(a, "pve1").Path == PathDirect })
	eventually(t, "direct path pve1->laptop", func() bool { return peerStatus(b, "laptop").Path == PathDirect })
	snap := a.fake.Snapshot()
	p, ok := snap.Peer(b.pub)
	if !ok || !slices.Contains(p.AllowedIPs, "10.144.0.3/32") {
		t.Fatalf("laptop's peer for pve1 = %+v", p)
	}
	if p.Endpoint != "192.168.1.20:41820" {
		t.Errorf("pve1 endpoint = %q, want its LAN address", p.Endpoint)
	}
	if snap.Address.String() != "10.144.0.2/16" {
		t.Errorf("laptop address = %s", snap.Address)
	}
	if snap.Filter || b.fake.Snapshot().Filter {
		t.Error("a mesh without acl.json got an access filter")
	}

	// Names land in the hosts file, next to what was there.
	eventually(t, "hosts file", func() bool {
		h, _ := os.ReadFile(a.hosts)
		return strings.Contains(string(h), "10.144.0.3\tpve1 pve1.wgh") &&
			strings.Contains(string(h), "127.0.0.1 localhost") && strings.Contains(string(h), "\trelay relay.wgh")
	})

	// The advertised route and exit node wait for approval.
	if p := peerStatus(a, "pve1"); len(p.Routes) != 0 || p.Exit {
		t.Fatalf("route visible before approval: %+v", p)
	}
	if !b.fake.Snapshot().Forward {
		t.Error("pve1 advertises a route but does not forward")
	}
	if _, _, err := r.srv.Approve("pve1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "approved route", func() bool { return slices.Contains(a.fake.Snapshot().Routes, "192.168.50.0/24") })
	p, _ = a.fake.Snapshot().Peer(b.pub)
	if !slices.Contains(p.AllowedIPs, "192.168.50.0/24") {
		t.Fatalf("route not on the direct peer: %+v", p)
	}

	// Use pve1 as the exit node.
	eventually(t, "exit approved", func() bool { return peerStatus(a, "pve1").Exit })
	if err := a.a.SetExitNode("pve1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "exit on", func() bool {
		p, _ := a.fake.Snapshot().Peer(b.pub)
		return a.fake.Snapshot().Exit && slices.Contains(p.AllowedIPs, "0.0.0.0/0")
	})
	if err := a.a.SetExitNode("nope"); err == nil {
		t.Error("unknown exit node accepted")
	}

	// Break the direct path: traffic falls back to the relay.
	r.net.Block(a.pub, "192.168.1.20:41820")
	r.net.Block(b.pub, "192.168.1.10:41820")
	r.clk.Add(4 * time.Minute)
	eventually(t, "relay fallback", func() bool { return peerStatus(a, "pve1").Path == PathRelay })
	p, _ = a.fake.Snapshot().Peer(b.pub)
	if len(p.AllowedIPs) != 0 {
		t.Fatalf("relayed peer still claims addresses: %+v", p)
	}
	relayPeer, _ := a.fake.Snapshot().Peer(r.srv.Status().Relay.PublicKey)
	if !slices.Contains(relayPeer.AllowedIPs, "10.144.0.0/16") || !slices.Contains(relayPeer.AllowedIPs, "192.168.50.0/24") {
		t.Fatalf("relay peer = %+v", relayPeer)
	}
	if a.fake.Snapshot().Exit {
		t.Error("exit through a relayed device should be off")
	}
	if st := a.a.Status(); !strings.Contains(st.ExitNote, "waiting for a direct path") {
		t.Errorf("exit note = %q", st.ExitNote)
	}

	// The path comes back by itself.
	r.net.Unblock(a.pub, "192.168.1.20:41820")
	r.net.Unblock(b.pub, "192.168.1.10:41820")
	eventually(t, "direct again", func() bool {
		r.clk.Add(TryEach) // let each side move on to its next candidate
		time.Sleep(30 * time.Millisecond)
		return peerStatus(a, "pve1").Path == PathDirect
	})

	// The relay can be the exit node too.
	if err := a.a.SetExitNode("relay"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "relay exit", func() bool {
		p, _ := a.fake.Snapshot().Peer(r.srv.Status().Relay.PublicKey)
		return slices.Contains(p.AllowedIPs, "0.0.0.0/0") && a.fake.Snapshot().Exit
	})

	// Key rotation reaches the other device.
	old := a.pub
	if err := a.a.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, _ := Load(a.path)
	if st.PublicKey == old {
		t.Fatal("key did not change")
	}
	eventually(t, "pve1 sees the new key", func() bool {
		_, oldThere := b.fake.Snapshot().Peer(old)
		_, newThere := b.fake.Snapshot().Peer(st.PublicKey)
		return !oldThere && newThere
	})

	// A phone joins through the relay.
	conf, err := r.srv.AddStatic("phone", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "Endpoint = relay.example:51820") || !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("phone config:\n%s", conf)
	}
	eventually(t, "phone listed", func() bool { return peerStatus(a, "phone").Static })

	// Removing pve1 stops its agent and takes its interface down.
	if err := r.srv.Remove("pve1"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-b.done:
		b.done <- err
		if !errors.Is(err, ErrRemoved) {
			t.Fatalf("pve1 agent ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("removed agent kept running")
	}
	if b.fake.Snapshot().Up {
		t.Error("removed device's interface is still up")
	}
	h, _ := os.ReadFile(b.hosts)
	if strings.Contains(string(h), "wgh") {
		t.Errorf("hosts block left behind:\n%s", h)
	}
	eventually(t, "laptop drops pve1", func() bool { _, ok := a.fake.Snapshot().Peer(b.pub); return !ok })
}

func TestJoinRejectsBadToken(t *testing.T) {
	r := newRig(t)
	tok, _ := r.srv.NewToken(time.Hour, false, false)
	dir := t.TempDir()
	if _, err := Join(context.Background(), filepath.Join(dir, "a.json"), JoinOptions{Token: tok, Name: "one"}); err != nil {
		t.Fatal(err)
	}
	// One-time tokens work once.
	if _, err := Join(context.Background(), filepath.Join(dir, "b.json"), JoinOptions{Token: tok, Name: "two"}); err == nil ||
		!strings.Contains(err.Error(), "unknown, used or expired") {
		t.Fatalf("second use: %v", err)
	}
	// Names are unique.
	tok2, _ := r.srv.NewToken(time.Hour, true, false)
	if _, err := Join(context.Background(), filepath.Join(dir, "c.json"), JoinOptions{Token: tok2, Name: "one"}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	// Expired tokens don't.
	r.clk.Add(2 * time.Hour)
	if _, err := Join(context.Background(), filepath.Join(dir, "d.json"), JoinOptions{Token: tok2, Name: "three"}); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := Join(context.Background(), filepath.Join(dir, "e.json"), JoinOptions{Token: "garbage", Name: "x"}); err == nil {
		t.Fatal("garbage token accepted")
	}
	fi, err := os.Stat(filepath.Join(dir, "a.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("agent state mode: %v %v", fi, err)
	}
}
