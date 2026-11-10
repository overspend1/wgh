package wgctl

import (
	"fmt"
	"os"
	"os/exec"
)

// NewSystem returns the backend for this machine: Linux here.
func NewSystem() Backend { return NewLinux() }

// Check reports whether this machine can run the Linux backend.
func Check() error {
	if os.Geteuid() != 0 {
		return errNeedRoot
	}
	for _, tool := range []string{"ip", "wg"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s is not installed: install iproute2 and wireguard-tools", tool)
		}
	}
	return nil
}
