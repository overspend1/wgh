package portmap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultGateway finds the IPv4 default gateway: /proc/net/route on Linux,
// 'route -n get default' on macOS. Other systems report an error.
func DefaultGateway() (netip.Addr, error) { return defaultGateway() }

// parseProcNetRoute picks the default route with the lowest metric from
// the contents of /proc/net/route. Addresses there are hex in host (little
// endian) byte order.
func parseProcNetRoute(r io.Reader) (netip.Addr, error) {
	const rtfUp, rtfGateway = 0x1, 0x2
	var best netip.Addr
	bestMetric := -1
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&(rtfUp|rtfGateway) != rtfUp|rtfGateway {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(raw))
		gw := netip.AddrFrom4(a)
		if gw.IsUnspecified() {
			continue
		}
		metric, err := strconv.Atoi(f[6])
		if err != nil {
			continue
		}
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = gw, metric
		}
	}
	if !best.IsValid() {
		return netip.Addr{}, errors.New("no IPv4 default route")
	}
	return best, nil
}

// parseDarwinRoute reads the gateway line of 'route -n get default'.
func parseDarwinRoute(out []byte) (netip.Addr, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok || strings.TrimSpace(k) != "gateway" {
			continue
		}
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil || !a.Unmap().Is4() || a.IsUnspecified() {
			return netip.Addr{}, errors.New("default route has no IPv4 gateway")
		}
		return a.Unmap(), nil
	}
	return netip.Addr{}, errors.New("no default route")
}
