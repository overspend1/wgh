package wgctl

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// NewSystem returns the backend for this machine: Darwin here.
func NewSystem() Backend {
	addToolPath()
	return NewDarwin()
}

// Check reports whether this machine can run the macOS backend.
func Check() error {
	addToolPath()
	return checkDarwin(os.Geteuid(), exec.LookPath)
}

// addToolPath puts Homebrew's bin directories and /sbin on PATH when they
// are missing, as they can be under launchd or sudo, so wg and wireguard-go
// are found where 'brew install wireguard-tools' puts them.
func addToolPath() {
	dirs := filepath.SplitList(os.Getenv("PATH"))
	n := len(dirs)
	for _, d := range []string{"/opt/homebrew/bin", "/usr/local/bin", "/sbin"} {
		if slices.Contains(dirs, d) {
			continue
		}
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) != n {
		os.Setenv("PATH", strings.Join(dirs, string(os.PathListSeparator)))
	}
}
