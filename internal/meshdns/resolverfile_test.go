package meshdns

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolverFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "resolver")
	if err := WriteResolverFile(dir, "wgh", netip.MustParseAddr("10.144.0.2")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "wgh"))
	if !strings.Contains(string(b), "nameserver 10.144.0.2\n") {
		t.Fatalf("file = %q", b)
	}
	if err := RemoveResolverFile(dir, "wgh"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wgh")); !os.IsNotExist(err) {
		t.Fatal("file not removed")
	}
	// Someone else's file is left alone.
	os.WriteFile(filepath.Join(dir, "corp"), []byte("nameserver 1.2.3.4\n"), 0o644)
	if err := WriteResolverFile(dir, "corp", netip.MustParseAddr("10.144.0.2")); err == nil {
		t.Fatal("overwrote a foreign resolver file")
	}
	RemoveResolverFile(dir, "corp")
	if _, err := os.Stat(filepath.Join(dir, "corp")); err != nil {
		t.Fatal("removed a foreign resolver file")
	}
	if WriteResolverFile(dir, "../etc", netip.MustParseAddr("10.144.0.2")) == nil {
		t.Fatal("accepted a path as domain")
	}
}
