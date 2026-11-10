package portmap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// fakePMP answers PCP and/or NAT-PMP on 127.0.0.1.
type fakePMP struct {
	conn     *net.UDPConn
	pcp, pmp bool
	external netip.Addr
	garbage  []byte // when set, the reply to everything

	mu      sync.Mutex
	maps    map[uint16]uint16 // internal -> external
	deletes int
	seen    []byte // version byte of each request
}

func newFakePMP(t *testing.T, pcp, pmp bool, external string) *fakePMP {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePMP{conn: c, pcp: pcp, pmp: pmp, external: netip.MustParseAddr(external), maps: map[uint16]uint16{}}
	t.Cleanup(func() { c.Close() })
	go f.serve()
	return f
}

func (f *fakePMP) setGarbage(b []byte) { f.mu.Lock(); f.garbage = b; f.mu.Unlock() }

func (f *fakePMP) port() int { return f.conn.LocalAddr().(*net.UDPAddr).Port }

func (f *fakePMP) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if reply := f.answer(buf[:n]); reply != nil {
			f.conn.WriteToUDPAddrPort(reply, from)
		}
	}
}

func (f *fakePMP) answer(b []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(b) == 0 {
		return nil
	}
	f.seen = append(f.seen, b[0])
	if f.garbage != nil {
		return f.garbage
	}
	switch {
	case b[0] == pcpVersion && f.pcp && len(b) >= pcpMapLen && b[1] == pcpOpMap:
		r := make([]byte, pcpMapLen)
		copy(r, b)
		r[1] = pcpReply | pcpOpMap
		r[2], r[3] = 0, 0
		life := binary.BigEndian.Uint32(b[4:])
		internal := binary.BigEndian.Uint16(b[40:])
		ext := binary.BigEndian.Uint16(b[42:])
		if ext == 0 {
			ext = internal
		}
		if life == 0 {
			delete(f.maps, internal)
			f.deletes++
		} else {
			f.maps[internal] = ext
		}
		clear(r[8:24]) // epoch and reserved
		binary.BigEndian.PutUint16(r[42:], ext)
		a := f.external.As16()
		copy(r[44:], a[:])
		return r
	case b[0] == pcpVersion && f.pmp:
		// A NAT-PMP-only gateway: unsupported version, in NAT-PMP format.
		return []byte{0, pcpReply | b[1]&0x7f, 0, 1, 0, 0, 0, 1}
	case b[0] == pmpVersion && f.pmp && len(b) >= 2 && b[1] == pmpOpAddr:
		r := []byte{0, pcpReply | pmpOpAddr, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
		a := f.external.As4()
		copy(r[8:], a[:])
		return r
	case b[0] == pmpVersion && f.pmp && len(b) >= 12 && b[1] == pmpOpUDP:
		internal := binary.BigEndian.Uint16(b[4:])
		ext := binary.BigEndian.Uint16(b[6:])
		life := binary.BigEndian.Uint32(b[8:])
		if life == 0 {
			delete(f.maps, internal)
			f.deletes++
			ext = 0
		} else {
			if ext == 0 {
				ext = internal
			}
			f.maps[internal] = ext
		}
		r := make([]byte, 16)
		r[1] = pcpReply | pmpOpUDP
		binary.BigEndian.PutUint16(r[8:], internal)
		binary.BigEndian.PutUint16(r[10:], ext)
		binary.BigEndian.PutUint32(r[12:], life)
		return r
	}
	return nil
}

func (f *fakePMP) state() (maps map[uint16]uint16, deletes int, seen string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	maps = map[uint16]uint16{}
	for k, v := range f.maps {
		maps[k] = v
	}
	for _, v := range f.seen {
		seen += fmt.Sprint(v)
	}
	return maps, f.deletes, seen
}

// closedPort returns a UDP port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}

// fakeIGD is a UPnP router: an SSDP responder and an HTTP server.
type fakeIGD struct {
	ssdp     *net.UDPConn
	http     *httptest.Server
	external string
	service  string
	desc     string // overrides the description
	location string // overrides LOCATION
	taken    map[uint16]bool

	mu       sync.Mutex
	searches int
	maps     map[uint16]string // external port -> internal client:port
	deletes  []uint16
}

func newFakeIGD(t *testing.T, external string) *fakeIGD {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeIGD{ssdp: c, external: external, service: "urn:schemas-upnp-org:service:WANIPConnection:1",
		maps: map[uint16]string{}, taken: map[uint16]bool{}}
	g.http = httptest.NewServer(http.HandlerFunc(g.serveHTTP))
	t.Cleanup(func() { c.Close(); g.http.Close() })
	go g.serveSSDP()
	return g
}

// set changes the router's behaviour while it runs.
func (g *fakeIGD) set(f func(*fakeIGD)) { g.mu.Lock(); f(g); g.mu.Unlock() }

func (g *fakeIGD) addr() string { return g.ssdp.LocalAddr().String() }

func (g *fakeIGD) serveSSDP() {
	buf := make([]byte, 2048)
	for {
		n, from, err := g.ssdp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if !strings.HasPrefix(string(buf[:n]), "M-SEARCH") {
			continue
		}
		g.mu.Lock()
		g.searches++
		loc := g.location
		g.mu.Unlock()
		if loc == "" {
			loc = g.http.URL + "/desc.xml"
		}
		g.ssdp.WriteToUDPAddrPort([]byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: upnp:rootdevice\r\n"+
			"LOCATION: "+loc+"\r\n\r\n"), from)
	}
}

const descTmpl = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3f</controlURL></service></serviceList>
  <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList><service><serviceType>%s</serviceType><controlURL>/ctl/IPConn</controlURL></service></serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>`

func (g *fakeIGD) serveHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	desc, service, external := g.desc, g.service, g.external
	g.mu.Unlock()
	if r.Method == "GET" && r.URL.Path == "/desc.xml" {
		if desc != "" {
			io.WriteString(w, desc)
			return
		}
		fmt.Fprintf(w, descTmpl, service)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/ctl/IPConn" {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	vals, err := soapValues(body)
	if err != nil {
		http.Error(w, "bad xml", 400)
		return
	}
	action := r.Header.Get("SOAPAction")
	_, action, _ = strings.Cut(strings.Trim(action, `"`), "#")
	fault := func(code int) {
		w.WriteHeader(500)
		fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>`+
			`<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">`+
			`<errorCode>%d</errorCode><errorDescription>nope</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code)
	}
	reply := func(inner string) {
		fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>`+
			`<u:%sResponse xmlns:u="%s">%s</u:%sResponse></s:Body></s:Envelope>`, action, service, inner, action)
	}
	var port uint16
	fmt.Sscan(vals["NewExternalPort"], &port)
	g.mu.Lock()
	defer g.mu.Unlock()
	switch action {
	case "AddPortMapping":
		if g.taken[port] || vals["NewProtocol"] != "UDP" {
			fault(upnpConflict)
			return
		}
		g.maps[port] = vals["NewInternalClient"] + ":" + vals["NewInternalPort"]
		reply("")
	case "GetExternalIPAddress":
		reply("<NewExternalIPAddress>" + external + "</NewExternalIPAddress>")
	case "DeletePortMapping":
		delete(g.maps, port)
		g.deletes = append(g.deletes, port)
		reply("")
	default:
		fault(401)
	}
}

func (g *fakeIGD) state() (maps map[uint16]string, deletes []uint16, searches int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	maps = map[uint16]string{}
	for k, v := range g.maps {
		maps[k] = v
	}
	return maps, append([]uint16(nil), g.deletes...), g.searches
}
