package meshdns

import (
	"fmt"
	"net/netip"
	"os/exec"

	"github.com/overspend1/wgh/internal/wgctl"
)

// lookPath is replaced in tests.
var lookPath = exec.LookPath

// Configure points systemd-resolved at server for domain on the link iface.
// The plain domain (not ~domain) also makes it a search domain, so a bare
// device name like "pve1" resolves. The link is taken off the default route
// so names outside the mesh never reach the mesh server, which would refuse
// them. On failure it reverts what it set.
func Configure(run wgctl.Runner, iface string, server netip.Addr, domain string) error {
	steps := [][]string{
		{"dns", iface, server.String()},
		{"domain", iface, domain},
		{"default-route", iface, "false"},
	}
	for _, args := range steps {
		if _, err := run(nil, "resolvectl", args...); err != nil {
			_ = Unconfigure(run, iface)
			return fmt.Errorf("configure systemd-resolved: %w", err)
		}
	}
	return nil
}

// Unconfigure drops the DNS settings of iface from systemd-resolved.
func Unconfigure(run wgctl.Runner, iface string) error {
	if _, err := run(nil, "resolvectl", "revert", iface); err != nil {
		return fmt.Errorf("revert systemd-resolved: %w", err)
	}
	return nil
}

// Available reports whether resolvectl is installed and systemd-resolved
// answers it.
func Available(run wgctl.Runner) bool {
	if _, err := lookPath("resolvectl"); err != nil {
		return false
	}
	_, err := run(nil, "resolvectl", "status")
	return err == nil
}
