package portmap

import (
	"net/netip"
	"os"
)

func defaultGateway() (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()
	return parseProcNetRoute(f)
}
