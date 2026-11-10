package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderHosts(t *testing.T) {
	base := "127.0.0.1 localhost\n::1 localhost\n"
	got := RenderHosts(base, []HostEntry{{"10.144.0.3", "pve1"}, {"10.144.0.2", "laptop"}}, "wgh")
	want := "127.0.0.1 localhost\n::1 localhost\n\n" + hostsBegin + "\n" +
		"10.144.0.2\tlaptop laptop.wgh\n10.144.0.3\tpve1 pve1.wgh\n" + hostsEnd + "\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
	// Replacing is stable and removing restores the original.
	if again := RenderHosts(got, []HostEntry{{"10.144.0.2", "laptop"}, {"10.144.0.3", "pve1"}}, "wgh"); again != got {
		t.Fatalf("not stable:\n%s", again)
	}
	if back := RenderHosts(got, nil, ""); back != base {
		t.Fatalf("removal left:\n%q", back)
	}
}

func TestWriteHostsKeepsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(p, []byte("127.0.0.1 localhost\n"), 0o644)
	if err := WriteHosts(p, []HostEntry{{"10.144.0.2", "a"}}, "wgh"); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temp files left: %d entries", len(entries))
	}
}
