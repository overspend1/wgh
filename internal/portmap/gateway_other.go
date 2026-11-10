//go:build !linux && !darwin

package portmap

import (
	"errors"
	"net/netip"
	"runtime"
)

func defaultGateway() (netip.Addr, error) {
	return netip.Addr{}, errors.New("finding the default gateway is not supported on " + runtime.GOOS)
}
