package agent

import (
	"syscall"

	"github.com/overspend1/wgh/internal/wgctl"
)

// markControl marks the agent's own connections to the coordinator like
// WireGuard's packets, so they skip an exit node and keep working even when
// the tunnel is broken. Without root the mark is simply not set.
func markControl(_, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, wgctl.FwMark)
	})
}
