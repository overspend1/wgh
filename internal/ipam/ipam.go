// Package ipam allocates tunnel addresses inside an IPv4 subnet.
package ipam

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrExhausted is returned when every usable address in the subnet is taken.
var ErrExhausted = errors.New("no free addresses left in subnet")

// ParseSubnet parses an IPv4 CIDR, masks it to its network address and checks
// that it leaves room for a server and at least one peer.
func ParseSubnet(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse subnet %q: %w", cidr, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("subnet %q: only IPv4 subnets are supported", cidr)
	}
	if p.Bits() > 30 {
		return netip.Prefix{}, fmt.Errorf("subnet %q is too small: use /30 or larger", cidr)
	}
	return p.Masked(), nil
}

// First returns the first usable host address (network address + 1), which
// is the conventional address for the server.
func First(subnet netip.Prefix) netip.Addr {
	return subnet.Masked().Addr().Next()
}

// Broadcast returns the last address of the subnet.
func Broadcast(subnet netip.Prefix) netip.Addr {
	a := subnet.Masked().Addr().As4()
	hostBits := 32 - subnet.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= (1 << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Usable reports whether addr is inside subnet and is neither the network nor
// the broadcast address.
func Usable(subnet netip.Prefix, addr netip.Addr) bool {
	subnet = subnet.Masked()
	return addr.Is4() && subnet.Contains(addr) &&
		addr != subnet.Addr() && addr != Broadcast(subnet)
}

// Next returns the lowest usable address in subnet that is not in used.
func Next(subnet netip.Prefix, used []netip.Addr) (netip.Addr, error) {
	subnet = subnet.Masked()
	taken := make(map[netip.Addr]bool, len(used))
	for _, a := range used {
		taken[a] = true
	}
	last := Broadcast(subnet)
	for a := First(subnet); a.IsValid() && a.Less(last); a = a.Next() {
		if !taken[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrExhausted
}

// Claim checks that a manually chosen address is usable and free.
func Claim(subnet netip.Prefix, addr netip.Addr, used []netip.Addr) error {
	if !Usable(subnet, addr) {
		return fmt.Errorf("%s is not a usable host address in %s", addr, subnet)
	}
	for _, a := range used {
		if a == addr {
			return fmt.Errorf("%s is already in use", addr)
		}
	}
	return nil
}
