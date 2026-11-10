package portmap

import (
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) {
	// Answers on loopback take microseconds; keep silent cases quick.
	udpWaits = []time.Duration{60 * time.Millisecond, 120 * time.Millisecond}
	ssdpWait = 300 * time.Millisecond
	os.Exit(m.Run())
}

func mapper(pmpPort int, ssdp string) *Mapper {
	return &Mapper{Gateway: func() (netip.Addr, error) { return loopback, nil }, Port: pmpPort, SSDPAddr: ssdp,
		Now: func() time.Time { return t0 }}
}

func TestPCP(t *testing.T) {
	gw := newFakePMP(t, true, true, "203.0.113.5")
	igd := newFakeIGD(t, "203.0.113.5")
	m := mapper(gw.port(), igd.addr())
	mp, err := m.Map(context.Background(), 41820, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if mp.Protocol != ProtoPCP || mp.External.String() != "203.0.113.5:41820" || !mp.Expires.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("mapping = %+v", mp)
	}
	// A renewal refreshes the same mapping (same nonce, same port).
	if mp2, err := m.Map(context.Background(), 41820, 2*time.Hour); err != nil || mp2.External != mp.External {
		t.Fatalf("renew = %+v, %v", mp2, err)
	}
	if maps, _, seen := gw.state(); maps[41820] != 41820 || seen != "22" {
		t.Fatalf("gateway maps %v, requests %q", maps, seen)
	}
	if _, _, n := igd.state(); n != 0 {
		t.Error("UPnP tried although PCP worked")
	}
	if err := m.Unmap(context.Background(), mp); err != nil {
		t.Fatal(err)
	}
	if maps, deletes, _ := gw.state(); len(maps) != 0 || deletes != 1 {
		t.Fatalf("after unmap: %v, %d deletes", maps, deletes)
	}
}

func TestNATPMPFallback(t *testing.T) {
	gw := newFakePMP(t, false, true, "198.51.100.9")
	igd := newFakeIGD(t, "198.51.100.9")
	m := mapper(gw.port(), igd.addr())
	mp, err := m.Map(context.Background(), 41820, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if mp.Protocol != ProtoNATPMP || mp.External.String() != "198.51.100.9:41820" || !mp.Expires.Equal(t0.Add(time.Hour)) {
		t.Fatalf("mapping = %+v", mp)
	}
	// PCP first (version 2), then NAT-PMP's two requests (version 0).
	if _, _, seen := gw.state(); seen != "200" {
		t.Errorf("request versions %q, want PCP then NAT-PMP", seen)
	}
	if _, _, n := igd.state(); n != 0 {
		t.Error("UPnP tried although NAT-PMP worked")
	}
	if err := m.Unmap(context.Background(), mp); err != nil {
		t.Fatal(err)
	}
	if maps, deletes, _ := gw.state(); len(maps) != 0 || deletes != 1 {
		t.Fatalf("after unmap: %v, %d deletes", maps, deletes)
	}
}

func TestUPnPFallback(t *testing.T) {
	igd := newFakeIGD(t, "203.0.113.5")
	m := mapper(closedPort(t), igd.addr())
	start := time.Now()
	mp, err := m.Map(context.Background(), 41820, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("Map took %v", time.Since(start))
	}
	if mp.Protocol != ProtoUPnP || mp.External.String() != "203.0.113.5:41820" || !mp.Expires.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("mapping = %+v", mp)
	}
	maps, _, _ := igd.state()
	if maps[41820] != "127.0.0.1:41820" {
		t.Fatalf("router maps %v", maps)
	}
	if err := m.Unmap(context.Background(), mp); err != nil {
		t.Fatal(err)
	}
	if maps, deletes, _ := igd.state(); len(maps) != 0 || len(deletes) != 1 || deletes[0] != 41820 {
		t.Fatalf("after unmap: %v, deletes %v", maps, deletes)
	}
}

func TestUPnPPortTaken(t *testing.T) {
	igd := newFakeIGD(t, "203.0.113.5")
	igd.set(func(g *fakeIGD) { g.taken[41820] = true })
	m := mapper(closedPort(t), igd.addr())
	mp, err := m.Map(context.Background(), 41820, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p := mp.External.Port()
	if p == 41820 || p < 32768 {
		t.Fatalf("external port %d", p)
	}
	if maps, _, _ := igd.state(); maps[p] != "127.0.0.1:41820" {
		t.Fatalf("router maps %v", maps)
	}
}

func TestDoubleNAT(t *testing.T) {
	for _, ext := range []string{"192.168.0.5", "100.64.1.1", "0.0.0.0", "10.1.2.3"} {
		gw := newFakePMP(t, true, true, ext)
		m := mapper(gw.port(), "127.0.0.1:1")
		if _, err := m.Map(context.Background(), 41820, time.Hour); !errors.Is(err, ErrDoubleNAT) {
			t.Errorf("PCP %s: %v", ext, err)
		}
		if maps, deletes, _ := gw.state(); len(maps) != 0 || deletes != 1 {
			t.Errorf("PCP %s: mapping left behind: %v, %d deletes", ext, maps, deletes)
		}
		pmp := newFakePMP(t, false, true, ext)
		m = mapper(pmp.port(), "127.0.0.1:1")
		if _, err := m.Map(context.Background(), 41820, time.Hour); !errors.Is(err, ErrDoubleNAT) {
			t.Errorf("NAT-PMP %s: %v", ext, err)
		}
		if maps, _, _ := pmp.state(); len(maps) != 0 {
			t.Errorf("NAT-PMP %s: mapped anyway: %v", ext, maps)
		}
	}
	igd := newFakeIGD(t, "100.100.1.1")
	m := mapper(closedPort(t), igd.addr())
	if _, err := m.Map(context.Background(), 41820, time.Hour); !errors.Is(err, ErrDoubleNAT) || err.Error() == "" ||
		!strings.Contains(err.Error(), "double NAT, mapping not useful") {
		t.Errorf("UPnP: %v", err)
	}
	if maps, deletes, _ := igd.state(); len(maps) != 0 || len(deletes) != 1 {
		t.Errorf("UPnP mapping left behind: %v %v", maps, deletes)
	}
}

func TestNothingFound(t *testing.T) {
	m := mapper(closedPort(t), "127.0.0.1:"+itoa(closedPort(t)))
	start := time.Now()
	_, err := m.Map(context.Background(), 41820, time.Hour)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	m.Gateway = func() (netip.Addr, error) { return netip.Addr{}, errors.New("no route") }
	if _, err := m.Map(context.Background(), 41820, time.Hour); !errors.Is(err, ErrNoGateway) {
		t.Fatalf("err = %v", err)
	}
	// The whole call is bounded.
	silent := newFakePMP(t, false, false, "203.0.113.5")
	m = mapper(silent.port(), "127.0.0.1:"+itoa(closedPort(t)))
	m.Timeout = 300 * time.Millisecond
	start = time.Now()
	if _, err := m.Map(context.Background(), 41820, time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("Timeout not honoured: %v", time.Since(start))
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestMalformedReplies(t *testing.T) {
	garbage := [][]byte{
		{2, 0x81},                // PCP header cut short
		{2, 0x81, 0, 0, 0, 0},    // still short
		{0, 0x80},                // NAT-PMP address reply cut short
		{0, 0x81, 0, 0, 1, 2, 3}, // NAT-PMP map reply cut short
		{0xff, 0xff, 0xff},
		make([]byte, 1100),
	}
	for i, g := range garbage {
		gw := newFakePMP(t, true, true, "203.0.113.5")
		gw.setGarbage(g)
		m := mapper(gw.port(), "127.0.0.1:"+itoa(closedPort(t)))
		m.Timeout = 2 * time.Second
		if _, err := m.Map(context.Background(), 41820, time.Hour); !errors.Is(err, ErrNotFound) {
			t.Errorf("garbage %d: %v", i, err)
		}
	}

	// UPnP: a broken description, a location elsewhere, a description
	// without the service.
	for i, mod := range []func(*fakeIGD){
		func(g *fakeIGD) { g.desc = "<root><device><serviceList><service>" },
		func(g *fakeIGD) { g.location = "http://192.0.2.1:80/desc.xml" },
		func(g *fakeIGD) { g.location = "ftp://127.0.0.1/desc.xml" },
		func(g *fakeIGD) { g.service = "urn:schemas-upnp-org:service:Layer3Forwarding:1" },
		func(g *fakeIGD) { g.external = "not an address" },
	} {
		igd := newFakeIGD(t, "203.0.113.5")
		igd.set(mod)
		m := mapper(closedPort(t), igd.addr())
		if _, err := m.Map(context.Background(), 41820, time.Hour); !errors.Is(err, ErrNotFound) {
			t.Errorf("UPnP case %d: %v", i, err)
		}
	}

	// The parsers never panic, whatever they get.
	r := rand.New(rand.NewSource(1))
	loc, _ := url.Parse("http://127.0.0.1:5000/d.xml")
	for i := 0; i < 5000; i++ {
		b := make([]byte, r.Intn(80))
		r.Read(b)
		if len(b) > 0 && r.Intn(2) == 0 {
			b[0] = []byte{0, 2}[r.Intn(2)]
		}
		parsePCPMap(b)
		parsePMPAddr(b)
		parsePMPMap(b)
		parseSSDP(b, loopback)
		findService(b, loc)
		soapValues(b)
		parseDarwinRoute(b)
		parseProcNetRoute(strings.NewReader(string(b)))
	}
	for n := 0; n <= pcpMapLen; n++ {
		ok := pcpMapRequest(loopback, [12]byte{}, 1, 1, 1)
		ok[1] |= pcpReply
		parsePCPMap(ok[:n])
	}
}

func TestUsable(t *testing.T) {
	for s, want := range map[string]bool{"203.0.113.5": true, "8.8.8.8": true, "10.0.0.1": false, "172.16.4.4": false,
		"192.168.1.1": false, "100.64.0.1": false, "100.127.255.255": false, "100.128.0.1": true, "0.0.0.0": false,
		"127.0.0.1": false, "169.254.1.1": false, "224.0.0.1": false, "2001:db8::1": false, "::ffff:203.0.113.5": true} {
		if got := Usable(netip.MustParseAddr(s)); got != want {
			t.Errorf("Usable(%s) = %v", s, got)
		}
	}
}
