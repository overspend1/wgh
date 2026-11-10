// Package portmap asks the home router to forward a UDP port to this
// device, so other devices can reach it directly even behind a NAT that
// gives every destination a different outside port. It speaks PCP
// (RFC 6887), NAT-PMP (RFC 6886) and UPnP IGD, in that order, using only
// the standard library.
package portmap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Protocol names in Mapping.Protocol.
const (
	ProtoPCP    = "PCP"
	ProtoNATPMP = "NAT-PMP"
	ProtoUPnP   = "UPnP"
)

var (
	// ErrNoGateway means the default gateway could not be found.
	ErrNoGateway = errors.New("no default gateway")
	// ErrNotFound means the gateway speaks none of the protocols.
	ErrNotFound = errors.New("no port-mapping gateway found")
	// ErrDoubleNAT means the gateway mapped (or would map) the port on an
	// address that is itself behind another NAT, so the mapping is useless.
	ErrDoubleNAT = errors.New("double NAT, mapping not useful")
)

// Mapping is a port forwarded on the router.
type Mapping struct {
	Protocol string         // ProtoPCP, ProtoNATPMP or ProtoUPnP
	External netip.AddrPort // where the rest of the internet reaches the port
	Expires  time.Time

	// What Unmap needs.
	gateway  netip.Addr
	internal uint16
	nonce    [12]byte
	control  string // UPnP control URL
	service  string // UPnP service type
}

// Mapper creates and removes port mappings. The zero value works; the
// fields override the defaults, mostly for tests.
type Mapper struct {
	// Gateway finds the router. Nil means DefaultGateway.
	Gateway func() (netip.Addr, error)
	// Port of PCP and NAT-PMP on the gateway; 0 means 5351.
	Port int
	// SSDPAddr is where UPnP discovery is sent; "" means
	// 239.255.255.250:1900.
	SSDPAddr string
	// HTTP fetches UPnP descriptions and makes SOAP calls; nil means a
	// client with a short timeout and no proxy.
	HTTP *http.Client
	// Timeout bounds one Map call; 0 means 6 seconds.
	Timeout time.Duration
	Now     func() time.Time
	// Description is the UPnP mapping's label; "" means "wgh".
	Description string

	mu    sync.Mutex
	nonce [12]byte // one per Mapper, so PCP renewals refresh the same mapping
	init  bool
	last  uint16 // last external port, suggested again on renewal
}

// Steps get short timeouts: a router answers on the LAN in milliseconds.
var (
	udpWaits    = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond}
	ssdpWait    = time.Second
	httpTimeout = time.Second
)

const defaultPort = 5351

func (m *Mapper) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Mapper) port() int {
	if m.Port != 0 {
		return m.Port
	}
	return defaultPort
}

func (m *Mapper) httpClient() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{
		Timeout: httpTimeout,
		// The router is on the LAN: never send this through a proxy.
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
			DialContext: (&net.Dialer{Timeout: httpTimeout}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (m *Mapper) state() (nonce [12]byte, last uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.init {
		_, _ = rand.Read(m.nonce[:])
		m.init = true
	}
	return m.nonce, m.last
}

// Map forwards a UDP port on the router to internalPort on this device for
// about lifetime, trying PCP, then NAT-PMP, then UPnP IGD. Call it again
// before Expires to renew.
func (m *Mapper) Map(ctx context.Context, internalPort int, lifetime time.Duration) (Mapping, error) {
	if internalPort <= 0 || internalPort > 65535 {
		return Mapping{}, fmt.Errorf("portmap: bad port %d", internalPort)
	}
	if lifetime < time.Second {
		lifetime = time.Second
	}
	timeout := m.Timeout
	if timeout == 0 {
		timeout = 6 * time.Second
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	find := m.Gateway
	if find == nil {
		find = DefaultGateway
	}
	gw, err := find()
	if err != nil {
		return Mapping{}, fmt.Errorf("%w: %v", ErrNoGateway, err)
	}
	gw = gw.Unmap()
	if !gw.Is4() {
		return Mapping{}, fmt.Errorf("%w: %s is not IPv4", ErrNoGateway, gw)
	}
	try := []struct {
		name string
		f    func(context.Context, netip.Addr, uint16, time.Duration) (Mapping, error)
	}{{ProtoPCP, m.mapPCP}, {ProtoNATPMP, m.mapPMP}, {ProtoUPnP, m.mapUPnP}}
	var errs []string
	for _, t := range try {
		mp, err := t.f(ctx, gw, uint16(internalPort), lifetime)
		if err == nil {
			m.mu.Lock()
			m.last = mp.External.Port()
			m.mu.Unlock()
			return mp, nil
		}
		if errors.Is(err, ErrDoubleNAT) {
			return Mapping{}, err
		}
		if parent.Err() != nil {
			return Mapping{}, parent.Err()
		}
		errs = append(errs, t.name+": "+err.Error())
	}
	return Mapping{}, fmt.Errorf("%w (%s)", ErrNotFound, strings.Join(errs, "; "))
}

// Unmap removes a mapping made by Map.
func (m *Mapper) Unmap(ctx context.Context, mp Mapping) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	switch mp.Protocol {
	case ProtoPCP:
		return m.unmapPCP(ctx, mp)
	case ProtoNATPMP:
		return m.unmapPMP(ctx, mp)
	case ProtoUPnP:
		return m.unmapUPnP(ctx, mp)
	}
	return fmt.Errorf("portmap: unknown protocol %q", mp.Protocol)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Usable reports whether a is a public IPv4 address worth handing out: not
// private, CGNAT, loopback, link-local, multicast or unspecified.
func Usable(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.Is4() && !a.IsUnspecified() && !a.IsPrivate() && !a.IsLoopback() &&
		!a.IsLinkLocalUnicast() && !a.IsMulticast() && !cgnat.Contains(a) && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func doubleNAT(proto string, a netip.Addr) error {
	return fmt.Errorf("%w: %s gateway's external address is %s", ErrDoubleNAT, proto, a)
}

var errNoAnswer = errors.New("no answer")

// dial opens a UDP socket connected to the gateway.
func dial(ctx context.Context, gw netip.Addr, port int) (*net.UDPConn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", netip.AddrPortFrom(gw, uint16(port)).String())
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// exchange sends req and waits for a reply that accept likes, sending it
// again once. A refused port fails at once.
func exchange(ctx context.Context, c *net.UDPConn, req []byte, accept func([]byte) bool) ([]byte, error) {
	stop := context.AfterFunc(ctx, func() { _ = c.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	buf := make([]byte, 1500)
	for _, wait := range udpWaits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := c.Write(req); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(wait)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = c.SetReadDeadline(deadline)
		for {
			n, err := c.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				return nil, err
			}
			if accept(buf[:n]) {
				return append([]byte(nil), buf[:n]...), nil
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errNoAnswer
}

func localAddr(c net.Conn) netip.Addr {
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return ua.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

func lifeSecs(d time.Duration) uint32 {
	s := d / time.Second
	if s > 1<<32-1 {
		s = 1<<32 - 1
	}
	return uint32(s)
}
