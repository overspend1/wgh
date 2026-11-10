package meshdns

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// ResolverDir is where macOS looks for per-domain resolvers.
const ResolverDir = "/etc/resolver"

const resolverMark = "# Written by wgh; removed when wgh up stops.\n"

// WriteResolverFile makes macOS send lookups under domain to server, by
// writing dir/<domain> (see man 5 resolver). It refuses to replace a file
// wgh did not write.
func WriteResolverFile(dir, domain string, server netip.Addr) error {
	if domain == "" || strings.ContainsAny(domain, `/\`) || strings.HasPrefix(domain, ".") {
		return fmt.Errorf("bad domain %q", domain)
	}
	path := filepath.Join(dir, domain)
	if b, err := os.ReadFile(path); err == nil && !strings.HasPrefix(string(b), resolverMark) {
		return fmt.Errorf("%s exists and was not written by wgh; leaving it alone", path)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body := resolverMark + "nameserver " + server.String() + "\nport 53\n"
	tmp := path + ".wgh-tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemoveResolverFile removes dir/<domain> if wgh wrote it.
func RemoveResolverFile(dir, domain string) error {
	path := filepath.Join(dir, domain)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(b), resolverMark) {
		return nil
	}
	return os.Remove(path)
}
