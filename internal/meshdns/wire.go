// Package meshdns is a small authoritative DNS server for the mesh domain.
// It answers A and AAAA queries for <device>.<domain> from the netmap and
// refuses everything else: it is not a recursive resolver. The wire format
// is written by hand with the standard library (RFC 1035, RFC 6891).
package meshdns

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// TTL is the time to live of every record served, in seconds. It is short
// because devices come and go.
const TTL = 10

// DNS constants used here.
const (
	typeA    = 1
	typeNS   = 2
	typeSOA  = 6
	typeAAAA = 28
	typeOPT  = 41
	typeIXFR = 251
	typeAXFR = 252
	typeANY  = 255

	classIN  = 1
	classANY = 255

	rcodeOK       = 0
	rcodeFormErr  = 1
	rcodeNXDomain = 3
	rcodeNotImp   = 4
	rcodeRefused  = 5
	rcodeBadVers  = 16 // extended, needs EDNS

	flagQR = 1 << 15
	flagAA = 1 << 10
	flagTC = 1 << 9
	flagRD = 1 << 8
	flagCD = 1 << 4

	headerLen = 12
	maxUDP    = 512  // without EDNS
	ednsSize  = 1232 // the UDP payload size this server advertises
	maxTCP    = 65535
	maxName   = 255
)

// ErrMalformed means a packet was dropped without an answer: it is too short
// to carry a header, or it is itself a response.
var ErrMalformed = errors.New("meshdns: malformed packet")

// query is the part of a request the server cares about.
type query struct {
	id     uint16
	flags  uint16
	qname  []byte   // wire form, as sent, including the root label
	labels [][]byte // lowercased
	qtype  uint16
	qclass uint16

	edns        bool
	ednsSize    uint16
	ednsVersion uint8
}

func (q *query) opcode() int { return int(q.flags>>11) & 0xF }

// parse reads a request. It returns ErrMalformed for packets that get no
// answer at all, and rcodeFormErr for packets that get a FORMERR. When the
// question was read, qname is set even if rcode is FORMERR.
func parse(msg []byte) (q query, rcode int, err error) {
	if len(msg) < headerLen {
		return q, 0, ErrMalformed
	}
	q.id = binary.BigEndian.Uint16(msg[0:])
	q.flags = binary.BigEndian.Uint16(msg[2:])
	if q.flags&flagQR != 0 {
		return q, 0, ErrMalformed
	}
	qd := binary.BigEndian.Uint16(msg[4:])
	an := binary.BigEndian.Uint16(msg[6:])
	ns := binary.BigEndian.Uint16(msg[8:])
	ar := binary.BigEndian.Uint16(msg[10:])
	if qd != 1 {
		return q, rcodeFormErr, nil
	}
	off := headerLen
	total := 0
	for {
		if off >= len(msg) {
			return q, rcodeFormErr, nil
		}
		l := int(msg[off])
		if l == 0 {
			off++
			total++
			break
		}
		if l&0xC0 != 0 { // no compression (or reserved label types) in a question
			return q, rcodeFormErr, nil
		}
		if off+1+l > len(msg) {
			return q, rcodeFormErr, nil
		}
		total += l + 1
		if total >= maxName {
			return q, rcodeFormErr, nil
		}
		q.labels = append(q.labels, lower(msg[off+1:off+1+l]))
		off += 1 + l
	}
	if off+4 > len(msg) {
		q.labels = nil
		return q, rcodeFormErr, nil
	}
	q.qname = msg[headerLen:off]
	q.qtype = binary.BigEndian.Uint16(msg[off:])
	q.qclass = binary.BigEndian.Uint16(msg[off+2:])
	off += 4

	for i := 0; i < int(an)+int(ns); i++ {
		var e error
		if off, _, _, _, _, e = readRR(msg, off); e != nil {
			return q, rcodeFormErr, nil
		}
	}
	for i := 0; i < int(ar); i++ {
		start := off
		var typ, class uint16
		var ttl uint32
		var e error
		off, typ, class, ttl, _, e = readRR(msg, off)
		if e != nil {
			return q, rcodeFormErr, nil
		}
		if typ != typeOPT {
			continue
		}
		if q.edns || msg[start] != 0 { // one OPT, owned by the root
			return q, rcodeFormErr, nil
		}
		q.edns = true
		q.ednsSize = class
		q.ednsVersion = uint8(ttl >> 16)
	}
	return q, rcodeOK, nil
}

// readRR skips one resource record and returns where the next one starts.
func readRR(msg []byte, off int) (next int, typ, class uint16, ttl uint32, rdata []byte, err error) {
	off, err = skipName(msg, off)
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	if off+10 > len(msg) {
		return 0, 0, 0, 0, nil, ErrMalformed
	}
	typ = binary.BigEndian.Uint16(msg[off:])
	class = binary.BigEndian.Uint16(msg[off+2:])
	ttl = binary.BigEndian.Uint32(msg[off+4:])
	rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
	off += 10
	if off+rdlen > len(msg) {
		return 0, 0, 0, 0, nil, ErrMalformed
	}
	return off + rdlen, typ, class, ttl, msg[off : off+rdlen], nil
}

// skipName steps over a possibly compressed name without following pointers.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, ErrMalformed
		}
		l := int(msg[off])
		switch l & 0xC0 {
		case 0xC0:
			if off+2 > len(msg) {
				return 0, ErrMalformed
			}
			return off + 2, nil
		case 0:
			if l == 0 {
				return off + 1, nil
			}
			off += 1 + l
		default:
			return 0, ErrMalformed
		}
	}
}

func lower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// rec is one record to write. owner is the offset of its name in the
// question, written as a compression pointer.
type rec struct {
	owner int
	typ   uint16
	data  []byte
}

func appendU16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func appendU32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }
func appendPtr(b []byte, off int) []byte  { return appendU16(b, 0xC000|uint16(off)) }

// appendLabelPtr writes one label followed by a pointer, like ns.<apex>.
func appendLabelPtr(b []byte, label string, off int) []byte {
	b = append(b, byte(len(label)))
	b = append(b, label...)
	return appendPtr(b, off)
}

func appendRR(b []byte, r rec) []byte {
	b = appendPtr(b, r.owner)
	b = appendU16(b, r.typ)
	b = appendU16(b, classIN)
	b = appendU32(b, TTL)
	b = appendU16(b, uint16(len(r.data)))
	return append(b, r.data...)
}

func addrData(a netip.Addr) []byte { return a.AsSlice() }

// build writes a response. With truncate set it leaves out every record
// but OPT and sets TC.
func build(q *query, rcode int, aa bool, ans, auth []rec, truncate bool) []byte {
	b := make([]byte, headerLen, 512)
	binary.BigEndian.PutUint16(b[0:], q.id)
	flags := uint16(flagQR) | q.flags&(0xF<<11|flagRD|flagCD) | uint16(rcode&0xF)
	if aa {
		flags |= flagAA
	}
	if truncate {
		flags |= flagTC
		ans, auth = nil, nil
	}
	binary.BigEndian.PutUint16(b[2:], flags)
	if q.qname != nil {
		binary.BigEndian.PutUint16(b[4:], 1)
		b = append(b, q.qname...)
		b = appendU16(b, q.qtype)
		b = appendU16(b, q.qclass)
	}
	binary.BigEndian.PutUint16(b[6:], uint16(len(ans)))
	binary.BigEndian.PutUint16(b[8:], uint16(len(auth)))
	for _, r := range ans {
		b = appendRR(b, r)
	}
	for _, r := range auth {
		b = appendRR(b, r)
	}
	if q.edns {
		binary.BigEndian.PutUint16(b[10:], 1)
		b = append(b, 0) // root
		b = appendU16(b, typeOPT)
		b = appendU16(b, ednsSize)
		b = appendU32(b, uint32(rcode>>4)<<24) // extended rcode, version 0, no flags
		b = appendU16(b, 0)
	}
	return b
}
