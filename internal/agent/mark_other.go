//go:build !linux

package agent

import "syscall"

func markControl(_, _ string, _ syscall.RawConn) error { return nil }
