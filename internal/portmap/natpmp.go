package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// NAT-PMP (RFC 6886): ask for the external address, then for a UDP mapping.
const (
	pmpOpAddr = 0
	pmpOpUDP  = 1
)

func pmpAddrRequest() []byte { return []byte{pmpVersion, pmpOpAddr} }

func pmpMapRequest(internal, suggest uint16, lifetime uint32) []byte {
	b := make([]byte, 12)
	b[0], b[1] = pmpVersion, pmpOpUDP
	binary.BigEndian.PutUint16(b[4:], internal)
	binary.BigEndian.PutUint16(b[6:], suggest)
	binary.BigEndian.PutUint32(b[8:], lifetime)
	return b
}

func pmpResult(b []byte, op byte, size int) error {
	if len(b) < 4 || b[0] != pmpVersion || b[1] != pcpReply|op {
		return errors.New("malformed NAT-PMP reply")
	}
	if code := binary.BigEndian.Uint16(b[2:]); code != 0 {
		return fmt.Errorf("NAT-PMP result code %d", code)
	}
	if len(b) < size {
		return errors.New("short NAT-PMP reply")
	}
	return nil
}

func parsePMPAddr(b []byte) (netip.Addr, error) {
	if err := pmpResult(b, pmpOpAddr, 12); err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4([4]byte(b[8:12])), nil
}

func parsePMPMap(b []byte) (internal, external uint16, lifetime uint32, err error) {
	if err := pmpResult(b, pmpOpUDP, 16); err != nil {
		return 0, 0, 0, err
	}
	return binary.BigEndian.Uint16(b[8:]), binary.BigEndian.Uint16(b[10:]), binary.BigEndian.Uint32(b[12:]), nil
}

func pmpAccept(op byte) func([]byte) bool {
	return func(b []byte) bool { return len(b) >= 2 && b[0] == pmpVersion && b[1] == pcpReply|op }
}

func (m *Mapper) pmpMap(ctx context.Context, c *net.UDPConn, internal, suggest uint16, lifetime uint32) (uint16, uint32, error) {
	b, err := exchange(ctx, c, pmpMapRequest(internal, suggest, lifetime), pmpAccept(pmpOpUDP))
	if err != nil {
		return 0, 0, err
	}
	in, ext, life, err := parsePMPMap(b)
	if err != nil {
		return 0, 0, err
	}
	if in != internal {
		return 0, 0, errors.New("NAT-PMP reply for another port")
	}
	return ext, life, nil
}

func (m *Mapper) mapPMP(ctx context.Context, gw netip.Addr, internal uint16, lifetime time.Duration) (Mapping, error) {
	c, err := dial(ctx, gw, m.port())
	if err != nil {
		return Mapping{}, err
	}
	defer c.Close()
	b, err := exchange(ctx, c, pmpAddrRequest(), pmpAccept(pmpOpAddr))
	if err != nil {
		return Mapping{}, err
	}
	ip, err := parsePMPAddr(b)
	if err != nil {
		return Mapping{}, err
	}
	if !Usable(ip) {
		return Mapping{}, doubleNAT(ProtoNATPMP, ip)
	}
	_, last := m.state()
	suggest := last
	if suggest == 0 {
		suggest = internal
	}
	ext, life, err := m.pmpMap(ctx, c, internal, suggest, lifeSecs(lifetime))
	if err != nil {
		return Mapping{}, err
	}
	if ext == 0 || life == 0 {
		return Mapping{}, errors.New("NAT-PMP gateway granted no mapping")
	}
	return Mapping{Protocol: ProtoNATPMP, External: netip.AddrPortFrom(ip, ext),
		Expires: m.now().Add(time.Duration(life) * time.Second), gateway: gw, internal: internal}, nil
}

func (m *Mapper) unmapPMP(ctx context.Context, mp Mapping) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	c, err := dial(ctx, mp.gateway, m.port())
	if err != nil {
		return err
	}
	defer c.Close()
	_, _, err = m.pmpMap(ctx, c, mp.internal, 0, 0)
	return err
}
