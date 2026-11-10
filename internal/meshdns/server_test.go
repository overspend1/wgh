package meshdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// makeQuery builds a query for name (dots between labels, trailing dot
// optional). ednsSize 0 means no OPT record.
func makeQuery(id uint16, name string, qtype uint16, ednsSize uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flagRD)
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = appendU16(b, qtype)
	b = appendU16(b, classIN)
	if ednsSize > 0 {
		binary.BigEndian.PutUint16(b[10:], 1)
		b = append(b, 0)
		b = appendU16(b, typeOPT)
		b = appendU16(b, ednsSize)
		b = appendU32(b, 0)
		b = appendU16(b, 0)
	}
	return b
}

type rr struct {
	name  string
	typ   uint16
	class uint16
	ttl   uint32
	data  []byte
	off   int // where rdata starts, for names inside it
}

type msg struct {
	id                uint16
	flags             uint16
	rcode             int
	qname             string
	qtype             uint16
	an, ns, ar        []rr
	raw               []byte
	aa, tc, rd, isRsp bool
}

// readName follows compression pointers, with a hop limit.
func readName(b []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	for hops := 0; hops < 64; hops++ {
		if off >= len(b) {
			return "", 0, errors.New("name past end")
		}
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, ".") + ".", end, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(b) {
				return "", 0, errors.New("pointer past end")
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:]) & 0x3FFF)
		default:
			if off+1+l > len(b) {
				return "", 0, errors.New("label past end")
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, errors.New("pointer loop")
}

func decode(t *testing.T, b []byte) msg {
	t.Helper()
	if len(b) < 12 {
		t.Fatalf("short response: %d bytes", len(b))
	}
	m := msg{raw: b, id: binary.BigEndian.Uint16(b), flags: binary.BigEndian.Uint16(b[2:])}
	m.rcode = int(m.flags & 0xF)
	m.aa, m.tc, m.rd, m.isRsp = m.flags&flagAA != 0, m.flags&flagTC != 0, m.flags&flagRD != 0, m.flags&flagQR != 0
	qd := binary.BigEndian.Uint16(b[4:])
	off := 12
	if qd == 1 {
		name, next, err := readName(b, off)
		if err != nil {
			t.Fatal(err)
		}
		m.qname, m.qtype = name, binary.BigEndian.Uint16(b[next:])
		off = next + 4
	}
	read := func(n uint16) []rr {
		var out []rr
		for i := 0; i < int(n); i++ {
			name, next, err := readName(b, off)
			if err != nil {
				t.Fatalf("record name: %v", err)
			}
			if next+10 > len(b) {
				t.Fatal("record header past end")
			}
			r := rr{name: name, typ: binary.BigEndian.Uint16(b[next:]), class: binary.BigEndian.Uint16(b[next+2:]),
				ttl: binary.BigEndian.Uint32(b[next+4:])}
			l := int(binary.BigEndian.Uint16(b[next+8:]))
			r.off = next + 10
			if r.off+l > len(b) {
				t.Fatal("rdata past end")
			}
			r.data = b[r.off : r.off+l]
			off = r.off + l
			out = append(out, r)
		}
		return out
	}
	m.an = read(binary.BigEndian.Uint16(b[6:]))
	m.ns = read(binary.BigEndian.Uint16(b[8:]))
	m.ar = read(binary.BigEndian.Uint16(b[10:]))
	if off != len(b) {
		t.Fatalf("%d trailing bytes", len(b)-off)
	}
	return m
}

func testServer() *Server {
	s := New("WGH.")
	s.SetRecords(map[string][]netip.Addr{
		"laptop": {netip.MustParseAddr("10.144.0.2")},
		"PVE1":   {netip.MustParseAddr("10.144.0.3"), netip.MustParseAddr("fd00::3")},
		"v6only": {netip.MustParseAddr("fd00::9")},
		"relay":  {netip.MustParseAddr("10.144.0.1")},
	})
	return s
}

func ask(t *testing.T, s *Server, name string, qtype uint16) msg {
	t.Helper()
	b, err := s.Answer(makeQuery(0x1234, name, qtype, 0))
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)
	if m.id != 0x1234 || !m.isRsp || !m.rd {
		t.Fatalf("header id=%x flags=%x", m.id, m.flags)
	}
	return m
}

func TestAnswers(t *testing.T) {
	s := testServer()
	cases := []struct {
		name   string
		qtype  uint16
		rcode  int
		aa     bool
		answer []string // A/AAAA addresses, or record types for others
		soa    bool     // SOA in the authority section
	}{
		{"pve1.wgh.", typeA, rcodeOK, true, []string{"10.144.0.3"}, false},
		{"PvE1.WgH", typeA, rcodeOK, true, []string{"10.144.0.3"}, false},
		{"pve1.wgh", typeAAAA, rcodeOK, true, []string{"fd00::3"}, false},
		{"pve1.wgh", typeANY, rcodeOK, true, []string{"10.144.0.3", "fd00::3"}, false},
		{"laptop.wgh", typeAAAA, rcodeOK, true, nil, true},
		{"laptop.wgh", 16 /* TXT */, rcodeOK, true, nil, true},
		{"v6only.wgh", typeA, rcodeOK, true, nil, true},
		{"relay.wgh", typeA, rcodeOK, true, []string{"10.144.0.1"}, false},
		{"nope.wgh", typeA, rcodeNXDomain, true, nil, true},
		{"x.pve1.wgh", typeA, rcodeNXDomain, true, nil, true},
		{"wgh", typeSOA, rcodeOK, true, []string{"SOA"}, false},
		{"wgh", typeNS, rcodeOK, true, []string{"NS"}, false},
		{"wgh", typeANY, rcodeOK, true, []string{"SOA", "NS"}, false},
		{"wgh", typeA, rcodeOK, true, nil, true},
		{"example.com", typeA, rcodeRefused, false, nil, false},
		{"pve1", typeA, rcodeRefused, false, nil, false},
		{"pve1.wgh.example", typeA, rcodeRefused, false, nil, false},
		{".", typeNS, rcodeRefused, false, nil, false},
		{"wgh", typeAXFR, rcodeRefused, false, nil, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/%d", c.name, c.qtype), func(t *testing.T) {
			m := ask(t, s, c.name, c.qtype)
			if m.rcode != c.rcode || m.aa != c.aa {
				t.Fatalf("rcode %d aa %v, want %d %v", m.rcode, m.aa, c.rcode, c.aa)
			}
			want := c.name
			if !strings.HasSuffix(want, ".") {
				want += "."
			}
			if m.qname != want || m.qtype != c.qtype {
				t.Errorf("question %q/%d echoed as %q/%d", want, c.qtype, m.qname, m.qtype)
			}
			var got []string
			for _, r := range m.an {
				if r.ttl != TTL || r.class != classIN {
					t.Errorf("ttl %d class %d", r.ttl, r.class)
				}
				if !strings.EqualFold(r.name, want) && r.typ != typeSOA && r.typ != typeNS {
					t.Errorf("owner %q, want %q", r.name, want)
				}
				switch r.typ {
				case typeA, typeAAAA:
					a, _ := netip.AddrFromSlice(r.data)
					got = append(got, a.String())
				case typeSOA:
					got = append(got, "SOA")
				case typeNS:
					got = append(got, "NS")
					ns, _, err := readName(m.raw, r.off)
					if err != nil || !strings.EqualFold(ns, "ns.wgh.") {
						t.Errorf("NS target %q %v", ns, err)
					}
				}
			}
			if strings.Join(got, ",") != strings.Join(c.answer, ",") {
				t.Errorf("answers %v, want %v", got, c.answer)
			}
			if hasSOA := len(m.ns) == 1 && m.ns[0].typ == typeSOA; hasSOA != c.soa || (!c.soa && len(m.ns) != 0) {
				t.Errorf("authority %+v, want SOA: %v", m.ns, c.soa)
			}
			if c.soa {
				soa := m.ns[0]
				if !strings.EqualFold(soa.name, "wgh.") {
					t.Errorf("SOA owner %q", soa.name)
				}
				mname, next, err := readName(m.raw, soa.off)
				if err != nil || !strings.EqualFold(mname, "ns.wgh.") {
					t.Errorf("SOA mname %q %v", mname, err)
				}
				rname, next, err := readName(m.raw, next)
				if err != nil || !strings.EqualFold(rname, "hostmaster.wgh.") {
					t.Errorf("SOA rname %q %v", rname, err)
				}
				if next+20 != soa.off+len(soa.data) {
					t.Errorf("SOA rdata length %d", len(soa.data))
				}
				if min := binary.BigEndian.Uint32(m.raw[next+16:]); min != TTL {
					t.Errorf("SOA minimum %d", min)
				}
			}
		})
	}
}

func TestQuestionCaseKept(t *testing.T) {
	m := ask(t, testServer(), "PvE1.WgH.", typeA)
	if m.qname != "PvE1.WgH." || m.an[0].name != "PvE1.WgH." {
		t.Fatalf("case not kept: %q %q", m.qname, m.an[0].name)
	}
}

func TestMultiLabelDomain(t *testing.T) {
	s := New("mesh.example.com")
	s.SetRecords(map[string][]netip.Addr{"nas": {netip.MustParseAddr("10.0.0.5")}})
	if m := ask(t, s, "nas.mesh.example.com", typeA); m.rcode != rcodeOK || len(m.an) != 1 {
		t.Fatalf("rcode %d answers %d", m.rcode, len(m.an))
	}
	if m := ask(t, s, "nas.example.com", typeA); m.rcode != rcodeRefused {
		t.Fatalf("outside the domain: rcode %d", m.rcode)
	}
	if m := ask(t, s, "mesh.example.com", typeSOA); m.rcode != rcodeOK || len(m.an) != 1 || m.an[0].name != "mesh.example.com." {
		t.Fatalf("apex SOA: %+v", m)
	}
	if New("").Domain() != "wgh" {
		t.Error("empty domain should mean wgh")
	}
}

func TestSetRecordsReplacesAndBumpsSerial(t *testing.T) {
	s := testServer()
	serial := func() uint32 {
		m := ask(t, s, "wgh", typeSOA)
		_, next, _ := readName(m.raw, m.an[0].off)
		_, next, _ = readName(m.raw, next)
		return binary.BigEndian.Uint32(m.raw[next:])
	}
	first := serial()
	s.SetRecords(map[string][]netip.Addr{"laptop": {netip.MustParseAddr("10.144.0.2")}})
	second := serial()
	if second == first {
		t.Error("serial did not change with the records")
	}
	s.SetRecords(map[string][]netip.Addr{"laptop": {netip.MustParseAddr("10.144.0.2")}})
	if serial() != second {
		t.Error("serial changed without a change")
	}
	if m := ask(t, s, "pve1.wgh", typeA); m.rcode != rcodeNXDomain {
		t.Errorf("removed name: rcode %d", m.rcode)
	}
	s.SetRecords(map[string][]netip.Addr{"bare": nil})
	if m := ask(t, s, "bare.wgh", typeA); m.rcode != rcodeOK || len(m.an) != 0 {
		t.Errorf("name without address: rcode %d answers %d", m.rcode, len(m.an))
	}
}

func TestEDNS(t *testing.T) {
	s := testServer()
	b, err := s.Answer(makeQuery(7, "pve1.wgh", typeA, 4096))
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)
	if len(m.ar) != 1 || m.ar[0].typ != typeOPT || m.ar[0].name != "." || m.ar[0].class != ednsSize || m.ar[0].ttl != 0 {
		t.Fatalf("OPT not echoed: %+v", m.ar)
	}
	if len(m.an) != 1 {
		t.Fatalf("answers %d", len(m.an))
	}
	// No OPT in, no OPT out.
	if m := ask(t, s, "pve1.wgh", typeA); len(m.ar) != 0 {
		t.Errorf("unexpected additional: %+v", m.ar)
	}
	// An unknown EDNS version gets BADVERS.
	q := makeQuery(8, "pve1.wgh", typeA, 1232)
	q[len(q)-5] = 1 // version byte of the OPT TTL
	b, _ = s.Answer(q)
	m = decode(t, b)
	if len(m.ar) != 1 || m.rcode != 0 || m.ar[0].ttl>>24 != 1 || len(m.an) != 0 {
		t.Fatalf("BADVERS: rcode %d opt %+v", m.rcode, m.ar)
	}
	// Two OPT records are a format error.
	q = makeQuery(9, "pve1.wgh", typeA, 1232)
	q = append(q, q[len(q)-11:]...)
	binary.BigEndian.PutUint16(q[10:], 2)
	b, _ = s.Answer(q)
	if m := decode(t, b); m.rcode != rcodeFormErr {
		t.Fatalf("two OPTs: rcode %d", m.rcode)
	}
}

func TestTruncation(t *testing.T) {
	s := New("wgh")
	var many []netip.Addr
	for i := 1; i <= 60; i++ {
		many = append(many, netip.AddrFrom4([4]byte{10, 144, 1, byte(i)}))
	}
	s.SetRecords(map[string][]netip.Addr{"big": many})

	b, _ := s.Answer(makeQuery(1, "big.wgh", typeA, 0))
	m := decode(t, b)
	if !m.tc || len(m.an) != 0 || len(b) > 512 || m.qname != "big.wgh." {
		t.Fatalf("plain UDP: tc %v answers %d size %d", m.tc, len(m.an), len(b))
	}
	b, _ = s.Answer(makeQuery(1, "big.wgh", typeA, 600))
	m = decode(t, b)
	if !m.tc || len(m.ar) != 1 || len(b) > 600 {
		t.Fatalf("EDNS 600: tc %v opt %d size %d", m.tc, len(m.ar), len(b))
	}
	b, _ = s.Answer(makeQuery(1, "big.wgh", typeA, 1232))
	m = decode(t, b)
	if m.tc || len(m.an) != 60 {
		t.Fatalf("EDNS 1232: tc %v answers %d size %d", m.tc, len(m.an), len(b))
	}
	b, _ = s.answer(makeQuery(1, "big.wgh", typeA, 0), true)
	if m := decode(t, b); m.tc || len(m.an) != 60 {
		t.Fatalf("TCP: tc %v answers %d", m.tc, len(m.an))
	}
}

func TestMalformed(t *testing.T) {
	s := testServer()
	good := makeQuery(5, "pve1.wgh", typeA, 1232)
	resp := func() []byte { b := append([]byte(nil), good...); b[2] |= 0x80; return b }()
	notQuery := append([]byte(nil), good...)
	notQuery[2] |= 2 << 3 // opcode STATUS
	twoQ := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(twoQ[4:], 2)
	noQ := append([]byte(nil), good[:12]...)
	binary.BigEndian.PutUint16(noQ[4:], 0)
	ptrQ := append(append([]byte(nil), good[:12]...), 0xC0, 0x0C, 0, 1, 0, 1)
	longName := makeQuery(5, strings.Repeat("a.", 130)+"wgh", typeA, 0)
	badLabel := append(append([]byte(nil), good[:12]...), 0x40, 0, 0, 1, 0, 1)
	chaos := makeQuery(5, "pve1.wgh", typeA, 0)
	binary.BigEndian.PutUint16(chaos[len(chaos)-2:], 3)

	drop := [][]byte{nil, {}, good[:11], resp}
	for i, b := range drop {
		if out, err := s.Answer(b); !errors.Is(err, ErrMalformed) || out != nil {
			t.Errorf("drop %d: %v %x", i, err, out)
		}
	}
	answered := []struct {
		name  string
		in    []byte
		rcode int
	}{
		{"opcode", notQuery, rcodeNotImp},
		{"two questions", twoQ, rcodeFormErr},
		{"no question", noQ, rcodeFormErr},
		{"pointer in question", ptrQ, rcodeFormErr},
		{"name too long", longName, rcodeFormErr},
		{"reserved label type", badLabel, rcodeFormErr},
		{"cut in qtype", good[:len(good)-13], rcodeFormErr},
		{"cut in OPT", good[:len(good)-3], rcodeFormErr},
		{"chaos class", chaos, rcodeRefused},
	}
	for _, c := range answered {
		out, err := s.Answer(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if m := decode(t, out); m.rcode != c.rcode || len(m.an) != 0 {
			t.Errorf("%s: rcode %d answers %d, want %d", c.name, m.rcode, len(m.an), c.rcode)
		}
	}
}

// TestNoPanics mutates valid queries at random and checks that every
// answer is a well-formed message.
func TestNoPanics(t *testing.T) {
	s := testServer()
	seeds := [][]byte{
		makeQuery(1, "pve1.wgh", typeA, 0),
		makeQuery(2, "laptop.wgh", typeAAAA, 1232),
		makeQuery(3, "wgh", typeANY, 4096),
		makeQuery(4, "nope.example.com", typeA, 0),
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), seeds[i%len(seeds)]...)
		switch rng.Intn(4) {
		case 0: // flip bytes
			for n := rng.Intn(4) + 1; n > 0; n-- {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
		case 1: // cut
			b = b[:rng.Intn(len(b)+1)]
		case 2: // append junk
			for n := rng.Intn(40); n > 0; n-- {
				b = append(b, byte(rng.Intn(256)))
			}
		case 3: // big counts
			binary.BigEndian.PutUint16(b[4+2*rng.Intn(4):], uint16(rng.Intn(65536)))
		}
		out, err := s.Answer(b)
		if err != nil {
			continue
		}
		if len(out) > 512 && (len(b) < 12 || !strings.Contains(string(b), "\x00\x00\x29")) {
			t.Fatalf("UDP answer of %d bytes to %x", len(out), b)
		}
		decode(t, out)
	}
}

func FuzzAnswer(f *testing.F) {
	f.Add(makeQuery(1, "pve1.wgh", typeA, 0))
	f.Add(makeQuery(2, "wgh", typeSOA, 1232))
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0xC0, 0x0C})
	s := testServer()
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := s.Answer(b)
		if err == nil {
			decode(t, out)
		}
	})
}

func TestServeUDPAndTCP(t *testing.T) {
	s := testServer()
	addr, err := s.Listen(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	if addr.Port() == 0 || addr.Addr() != netip.MustParseAddr("127.0.0.1") || s.Addr() != addr {
		t.Fatalf("bound %s", addr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, netip.AddrPort{}) }()

	// UDP.
	uc, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := uc.Write(makeQuery(11, "pve1.wgh", typeA, 0)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if m := decode(t, buf[:n]); m.id != 11 || len(m.an) != 1 {
		t.Fatalf("UDP answer %+v", m)
	}
	// Garbage gets nothing, and the server keeps going.
	uc.Write([]byte{1, 2, 3})
	uc.Write(makeQuery(12, "ns.wgh", typeA, 0))
	n, err = uc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if m := decode(t, buf[:n]); m.id != 12 || len(m.an) != 1 || !strings.HasSuffix(fmt.Sprint(m.an[0].data), "[127 0 0 1]") {
		t.Fatalf("ns.wgh should answer the listen address: %+v", m)
	}

	// TCP, two queries on one connection.
	tc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	for i, name := range []string{"laptop.wgh", "nope.wgh"} {
		q := makeQuery(uint16(20+i), name, typeA, 0)
		tc.Write(binary.BigEndian.AppendUint16(nil, uint16(len(q))))
		tc.Write(q)
		var l [2]byte
		if _, err := io.ReadFull(tc, l[:]); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(tc, resp); err != nil {
			t.Fatal(err)
		}
		m := decode(t, resp)
		if m.id != uint16(20+i) || (i == 0 && len(m.an) != 1) || (i == 1 && m.rcode != rcodeNXDomain) {
			t.Fatalf("TCP answer %d: %+v", i, m)
		}
	}

	if err := s.Serve(ctx, netip.AddrPort{}); err == nil {
		t.Error("second Serve accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
	if c, err := net.Dial("tcp", addr.String()); err == nil {
		c.Close()
		t.Error("TCP still accepting after Serve returned")
	}
}

func TestServeListensItself(t *testing.T) {
	// Taken port: Serve reports the error.
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	taken := busy.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := New("wgh").Serve(context.Background(), taken); err == nil {
		t.Fatal("Serve on a taken port succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New("wgh").Serve(ctx, netip.MustParseAddrPort("127.0.0.1:0")); err != nil {
		t.Fatal(err)
	}
}

func TestSetRecordsWhileServing(t *testing.T) {
	s := testServer()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			s.SetRecords(map[string][]netip.Addr{"pve1": {netip.AddrFrom4([4]byte{10, 144, 0, byte(i)})}})
		}
	}()
	for i := 0; i < 500; i++ {
		ask(t, s, "pve1.wgh", typeA)
	}
	<-done
}
