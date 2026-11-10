//go:build !linux && !darwin

package wgctl

// NewSystem returns the backend for this machine: none here, so every call
// fails with ErrUnsupportedOS.
func NewSystem() Backend { return Unsupported{} }

// Check reports that wgh up does not run on this system.
func Check() error { return ErrUnsupportedOS }
