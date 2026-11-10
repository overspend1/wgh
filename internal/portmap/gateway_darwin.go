package portmap

import (
	"context"
	"net/netip"
	"os/exec"
	"time"
)

func defaultGateway() (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return netip.Addr{}, err
	}
	return parseDarwinRoute(out)
}
