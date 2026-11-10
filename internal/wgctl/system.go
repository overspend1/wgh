package wgctl

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrUnsupportedOS is what Check and every Unsupported method return on a
// system with no backend.
var ErrUnsupportedOS = errors.New("wgh up runs on Linux and macOS; on this system use the WireGuard app with 'wgh admin phone'")

var errNeedRoot = errors.New("setting up the WireGuard interface needs root: run 'sudo wgh up' (or use --dry-run to see what it would do)")

// checkDarwin is Check on macOS, with the user id and PATH lookup passed in
// so it can be tested anywhere.
func checkDarwin(euid int, lookPath func(string) (string, error)) error {
	if euid != 0 {
		return errNeedRoot
	}
	for _, tool := range []string{"wg", "wireguard-go"} {
		if _, err := lookPath(tool); err != nil {
			return fmt.Errorf("%s is not installed: run 'brew install wireguard-tools', which brings wireguard-go too", tool)
		}
	}
	for _, tool := range []string{"ifconfig", "route"} {
		if _, err := lookPath(tool); err != nil {
			return fmt.Errorf("%s is not on PATH: it ships with macOS in /sbin, add that to PATH", tool)
		}
	}
	return nil
}

// Unsupported is the backend of a system wgh can't configure: every method
// fails with ErrUnsupportedOS.
type Unsupported struct{}

func (Unsupported) Up(Interface) error                    { return ErrUnsupportedOS }
func (Unsupported) SetPeers(Interface, []Peer) error      { return ErrUnsupportedOS }
func (Unsupported) Stats(string) ([]PeerStat, error)      { return nil, ErrUnsupportedOS }
func (Unsupported) SetRoutes(string, []string) error      { return ErrUnsupportedOS }
func (Unsupported) SetExit(string, bool) error            { return ErrUnsupportedOS }
func (Unsupported) SetForward(string, string, bool) error { return ErrUnsupportedOS }
func (Unsupported) Down(string) error                     { return ErrUnsupportedOS }
func (Unsupported) SetBypass(string, []netip.Addr) error  { return ErrUnsupportedOS }
