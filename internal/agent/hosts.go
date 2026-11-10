package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	hostsBegin = "# BEGIN wgh (managed by wgh up, edits here are replaced)"
	hostsEnd   = "# END wgh"
)

// HostEntry is one name in the hosts file.
type HostEntry struct {
	Address string
	Name    string
}

// RenderHosts replaces the wgh block in a hosts file with entries, or removes
// it when entries is empty. Everything else is kept as it was.
func RenderHosts(current string, entries []HostEntry, domain string) string {
	var keep []string
	in := false
	for _, line := range strings.Split(current, "\n") {
		switch {
		case strings.TrimSpace(line) == hostsBegin:
			in = true
		case in && strings.TrimSpace(line) == hostsEnd:
			in = false
		case !in:
			keep = append(keep, line)
		}
	}
	out := strings.TrimRight(strings.Join(keep, "\n"), "\n")
	if len(entries) == 0 {
		return out + "\n"
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	var b strings.Builder
	b.WriteString(out)
	if out != "" {
		b.WriteString("\n\n")
	}
	b.WriteString(hostsBegin + "\n")
	for _, e := range entries {
		if domain != "" {
			fmt.Fprintf(&b, "%s\t%s %s.%s\n", e.Address, e.Name, e.Name, domain)
		} else {
			fmt.Fprintf(&b, "%s\t%s\n", e.Address, e.Name)
		}
	}
	b.WriteString(hostsEnd + "\n")
	return b.String()
}

// WriteHosts updates the hosts file in place, keeping its mode. It writes
// through a temp file in the same directory and renames it over.
func WriteHosts(path string, entries []HostEntry, domain string) error {
	cur, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	next := RenderHosts(string(cur), entries, domain)
	if next == string(cur) {
		return nil
	}
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hosts-wgh-*")
	if err != nil {
		// Some systems (containers) bind-mount /etc/hosts; write in place.
		return os.WriteFile(path, []byte(next), mode)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(next); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return os.WriteFile(path, []byte(next), mode)
	}
	return nil
}
