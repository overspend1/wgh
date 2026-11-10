package meshdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Limits of the network side.
const (
	maxTCPConns = 64
	tcpIdle     = 10 * time.Second
)

// Server answers for one domain. Its zero value is not usable: call New.
type Server struct {
	domain string
	labels [][]byte

	mu      sync.RWMutex
	records map[string][]netip.Addr
	serial  uint32
	self    []netip.Addr // answers ns.<domain> unless a device has that name

	lmu     sync.Mutex
	udp     *net.UDPConn
	tcp     *net.TCPListener
	addr    netip.AddrPort
	serving bool
}

// New makes a server for domain, such as "wgh". An empty domain means "wgh".
func New(domain string) *Server {
	domain = strings.ToLower(strings.Trim(domain, "."))
	if domain == "" {
		domain = "wgh"
	}
	s := &Server{domain: domain, records: map[string][]netip.Addr{}, serial: 1}
	for _, l := range strings.Split(domain, ".") {
		s.labels = append(s.labels, []byte(l))
	}
	return s
}

// Domain is the domain the server answers for, without a trailing dot.
func (s *Server) Domain() string { return s.domain }

// SetRecords replaces every name the server knows. Keys are device names
// without the domain; they are matched case-insensitively. It is safe to
// call while the server is answering.
func (s *Server) SetRecords(records map[string][]netip.Addr) {
	next := make(map[string][]netip.Addr, len(records))
	for name, addrs := range records {
		name = strings.ToLower(name)
		for _, a := range addrs {
			if a.IsValid() {
				next[name] = append(next[name], a.Unmap())
			}
		}
		if _, ok := next[name]; !ok {
			next[name] = nil // the name exists, with no address
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !maps.EqualFunc(s.records, next, slices.Equal[[]netip.Addr]) {
		s.records = next
		s.serial++
	}
}

func (s *Server) lookup(name string) (addrs []netip.Addr, serial uint32, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	addrs, ok = s.records[name]
	if !ok && name == "ns" && len(s.self) > 0 {
		addrs, ok = s.self, true
	}
	return addrs, s.serial, ok
}

func (s *Server) currentSerial() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serial
}

// Answer returns the response to one query as it would be sent over UDP,
// truncated to 512 bytes, or to the EDNS payload size the query gives. It
// returns ErrMalformed, and no response, for packets to drop.
func (s *Server) Answer(query []byte) ([]byte, error) { return s.answer(query, false) }

func (s *Server) answer(msg []byte, tcp bool) ([]byte, error) {
	q, rcode, err := parse(msg)
	if err != nil {
		return nil, err
	}
	limit := maxTCP
	if !tcp {
		limit = maxUDP
		if q.edns && int(q.ednsSize) > maxUDP {
			limit = int(q.ednsSize)
		}
	}
	var aa bool
	var ans, auth []rec
	switch {
	case rcode != rcodeOK:
	case q.edns && q.ednsVersion != 0:
		rcode = rcodeBadVers
	case q.opcode() != 0:
		rcode = rcodeNotImp
	default:
		rcode, aa, ans, auth = s.decide(&q)
	}
	b := build(&q, rcode, aa, ans, auth, false)
	if len(b) > limit {
		b = build(&q, rcode, aa, ans, auth, true)
	}
	return b, nil
}

// decide works out the answer to a well-formed standard query.
func (s *Server) decide(q *query) (rcode int, aa bool, ans, auth []rec) {
	if q.qclass != classIN && q.qclass != classANY {
		return rcodeRefused, false, nil, nil
	}
	n, d := len(q.labels), len(s.labels)
	if n < d {
		return rcodeRefused, false, nil, nil
	}
	for i := range s.labels {
		if !bytes.Equal(q.labels[n-d+i], s.labels[i]) {
			return rcodeRefused, false, nil, nil
		}
	}
	if q.qtype == typeAXFR || q.qtype == typeIXFR {
		return rcodeRefused, false, nil, nil
	}
	apex := headerLen
	for _, l := range q.labels[:n-d] {
		apex += len(l) + 1
	}
	if n == d {
		soa, ns := s.soa(apex, s.currentSerial()), nsRec(apex)
		switch q.qtype {
		case typeSOA:
			return rcodeOK, true, []rec{soa}, nil
		case typeNS:
			return rcodeOK, true, []rec{ns}, nil
		case typeANY:
			return rcodeOK, true, []rec{soa, ns}, nil
		}
		return rcodeOK, true, nil, []rec{soa}
	}
	if n-d > 1 {
		return rcodeNXDomain, true, nil, []rec{s.soa(apex, s.currentSerial())}
	}
	addrs, serial, ok := s.lookup(string(q.labels[0]))
	if !ok {
		return rcodeNXDomain, true, nil, []rec{s.soa(apex, serial)}
	}
	for _, a := range addrs {
		switch {
		case a.Is4() && (q.qtype == typeA || q.qtype == typeANY):
			ans = append(ans, rec{owner: headerLen, typ: typeA, data: addrData(a)})
		case a.Is6() && (q.qtype == typeAAAA || q.qtype == typeANY):
			ans = append(ans, rec{owner: headerLen, typ: typeAAAA, data: addrData(a)})
		}
	}
	if len(ans) == 0 {
		return rcodeOK, true, nil, []rec{s.soa(apex, serial)}
	}
	return rcodeOK, true, ans, nil
}

func (s *Server) soa(apex int, serial uint32) rec {
	var d []byte
	d = appendLabelPtr(d, "ns", apex)
	d = appendLabelPtr(d, "hostmaster", apex)
	d = appendU32(d, serial)
	d = appendU32(d, 3600)  // refresh
	d = appendU32(d, 600)   // retry
	d = appendU32(d, 86400) // expire
	d = appendU32(d, TTL)   // negative answers live as long as positive ones
	return rec{owner: apex, typ: typeSOA, data: d}
}

func nsRec(apex int) rec {
	return rec{owner: apex, typ: typeNS, data: appendLabelPtr(nil, "ns", apex)}
}

// Listen binds UDP and TCP on addr and returns the bound address. With port
// 0, both get the same free port. Serve then uses these sockets.
func (s *Server) Listen(addr netip.AddrPort) (netip.AddrPort, error) {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	return s.listenLocked(addr)
}

func (s *Server) listenLocked(addr netip.AddrPort) (netip.AddrPort, error) {
	if s.udp != nil {
		return s.addr, errors.New("meshdns: already listening")
	}
	var lastErr error
	for range 20 {
		u, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
		if err != nil {
			return netip.AddrPort{}, err
		}
		bound := u.LocalAddr().(*net.UDPAddr).AddrPort()
		bound = netip.AddrPortFrom(bound.Addr().Unmap(), bound.Port())
		t, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(bound))
		if err != nil {
			u.Close()
			lastErr = err
			if addr.Port() != 0 {
				return netip.AddrPort{}, err
			}
			continue // the free UDP port is taken on TCP: try another
		}
		s.udp, s.tcp, s.addr = u, t, bound
		if a := bound.Addr(); a.IsValid() && !a.IsUnspecified() {
			s.mu.Lock()
			s.self = []netip.Addr{a}
			s.mu.Unlock()
		}
		return bound, nil
	}
	return netip.AddrPort{}, lastErr
}

// Addr is the bound address, once listening.
func (s *Server) Addr() netip.AddrPort {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	return s.addr
}

// Serve answers over UDP and TCP until ctx ends, then closes the sockets.
// It listens on addr first unless Listen was already called, in which case
// addr is ignored. A Server serves once.
func (s *Server) Serve(ctx context.Context, addr netip.AddrPort) error {
	s.lmu.Lock()
	if s.serving {
		s.lmu.Unlock()
		return errors.New("meshdns: already serving")
	}
	if s.udp == nil {
		if _, err := s.listenLocked(addr); err != nil {
			s.lmu.Unlock()
			return err
		}
	}
	s.serving = true
	u, t := s.udp, s.tcp
	s.lmu.Unlock()

	conns := &connSet{m: map[net.Conn]struct{}{}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.serveUDP(u) }()
	go func() { defer wg.Done(); s.serveTCP(t, conns, &wg) }()
	<-ctx.Done()
	u.Close()
	t.Close()
	conns.closeAll()
	wg.Wait()
	return nil
}

func (s *Server) serveUDP(u *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := u.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		resp, err := s.answer(buf[:n], false)
		if err != nil {
			continue
		}
		_, _ = u.WriteToUDPAddrPort(resp, from)
	}
}

func (s *Server) serveTCP(t *net.TCPListener, conns *connSet, wg *sync.WaitGroup) {
	for {
		c, err := t.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if !conns.add(c) {
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conns.remove(c)
			s.serveConn(c)
		}()
	}
}

// serveConn answers length-prefixed queries on one TCP connection until it
// goes idle or sends something unusable.
func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	var lenb [2]byte
	for {
		if err := c.SetDeadline(time.Now().Add(tcpIdle)); err != nil {
			return
		}
		if _, err := io.ReadFull(c, lenb[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(lenb[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		resp, err := s.answer(msg, true)
		if err != nil {
			return
		}
		out := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(resp)), uint16(len(resp)))
		if _, err := c.Write(append(out, resp...)); err != nil {
			return
		}
	}
}

type connSet struct {
	mu     sync.Mutex
	m      map[net.Conn]struct{}
	closed bool
}

func (cs *connSet) add(c net.Conn) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.closed || len(cs.m) >= maxTCPConns {
		return false
	}
	cs.m[c] = struct{}{}
	return true
}

func (cs *connSet) remove(c net.Conn) {
	cs.mu.Lock()
	delete(cs.m, c)
	cs.mu.Unlock()
}

func (cs *connSet) closeAll() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.closed = true
	for c := range cs.m {
		c.Close()
	}
}
