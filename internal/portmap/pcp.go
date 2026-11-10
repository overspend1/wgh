package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// PCP (RFC 6887): one MAP request and its answer.
const (
	pcpVersion  = 2
	pcpOpMap    = 1
	pcpReply    = 0x80
	pcpMapLen   = 60
	protoUDP    = 17
	pcpUnsuppV  = 1
	pmpVersion  = 0
	pcpResultOK = 0
)

var errUnsupported = errors.New("not supported by the gateway")

// pcpMapRequest builds a MAP request. client is this device's address as
// the gateway sees it; a zero lifetime deletes the mapping.
func pcpMapRequest(client netip.Addr, nonce [12]byte, internal, suggest uint16, lifetime uint32) []byte {
	b := make([]byte, pcpMapLen)
	b[0], b[1] = pcpVersion, pcpOpMap
	binary.BigEndian.PutUint32(b[4:], lifetime)
	c := client.As16() // IPv4 goes in as ::ffff:a.b.c.d
	copy(b[8:24], c[:])
	copy(b[24:36], nonce[:])
	b[36] = protoUDP
	binary.BigEndian.PutUint16(b[40:], internal)
	binary.BigEndian.PutUint16(b[42:], suggest)
	b[54], b[55] = 0xff, 0xff // suggested external address ::ffff:0.0.0.0: any IPv4
	return b
}

type pcpMapResult struct {
	lifetime uint32
	nonce    [12]byte
	internal uint16
	external netip.AddrPort
}

// parsePCPMap reads a MAP reply. A reply in NAT-PMP's format or with
// UNSUPP_VERSION means the gateway does not speak PCP.
func parsePCPMap(b []byte) (pcpMapResult, error) {
	var r pcpMapResult
	if len(b) >= 1 && b[0] == pmpVersion {
		return r, errUnsupported
	}
	if len(b) < 4 || b[0] != pcpVersion || b[1] != pcpReply|pcpOpMap {
		return r, errors.New("malformed PCP reply")
	}
	if code := b[3]; code != pcpResultOK {
		if code == pcpUnsuppV {
			return r, errUnsupported
		}
		return r, fmt.Errorf("PCP result code %d", code)
	}
	if len(b) < pcpMapLen {
		return r, errors.New("short PCP reply")
	}
	if b[36] != protoUDP {
		return r, errors.New("PCP reply for another protocol")
	}
	r.lifetime = binary.BigEndian.Uint32(b[4:])
	copy(r.nonce[:], b[24:36])
	r.internal = binary.BigEndian.Uint16(b[40:])
	ip := netip.AddrFrom16([16]byte(b[44:60])).Unmap()
	r.external = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[42:]))
	return r, nil
}

func pcpAccept(b []byte) bool {
	return len(b) >= 2 && (b[0] == pmpVersion || (b[0] == pcpVersion && b[1] == pcpReply|pcpOpMap))
}

func (m *Mapper) pcp(ctx context.Context, gw netip.Addr, nonce [12]byte, internal, suggest uint16, lifetime uint32) (pcpMapResult, error) {
	c, err := dial(ctx, gw, m.port())
	if err != nil {
		return pcpMapResult{}, err
	}
	defer c.Close()
	req := pcpMapRequest(localAddr(c), nonce, internal, suggest, lifetime)
	b, err := exchange(ctx, c, req, pcpAccept)
	if err != nil {
		return pcpMapResult{}, err
	}
	r, err := parsePCPMap(b)
	if err != nil {
		return r, err
	}
	if r.nonce != nonce || r.internal != internal {
		return r, errors.New("PCP reply for another mapping")
	}
	return r, nil
}

func (m *Mapper) mapPCP(ctx context.Context, gw netip.Addr, internal uint16, lifetime time.Duration) (Mapping, error) {
	nonce, last := m.state()
	suggest := last
	if suggest == 0 {
		suggest = internal
	}
	r, err := m.pcp(ctx, gw, nonce, internal, suggest, lifeSecs(lifetime))
	if err != nil {
		return Mapping{}, err
	}
	mp := Mapping{Protocol: ProtoPCP, External: r.external, Expires: m.now().Add(time.Duration(r.lifetime) * time.Second),
		gateway: gw, internal: internal, nonce: nonce}
	if r.lifetime == 0 || r.external.Port() == 0 {
		return Mapping{}, errors.New("PCP gateway granted no mapping")
	}
	if !Usable(r.external.Addr()) {
		_ = m.unmapPCP(context.WithoutCancel(ctx), mp)
		return Mapping{}, doubleNAT(ProtoPCP, r.external.Addr())
	}
	return mp, nil
}

func (m *Mapper) unmapPCP(ctx context.Context, mp Mapping) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err := m.pcp(ctx, mp.gateway, mp.nonce, mp.internal, 0, 0)
	return err
}
