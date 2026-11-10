package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/overspend1/wgh/internal/state"
)

func wgh(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(args, &out, &errOut)
	return out.String() + errOut.String(), err
}

func mustWgh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := wgh(t, args...)
	if err != nil {
		t.Fatalf("wgh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	st := filepath.Join(dir, "state.json")

	mustWgh(t, "init", "--state", st, "--endpoint", "home.example.net", "--subnet", "10.44.0.0/24", "--dns", "10.44.0.1")
	if _, err := wgh(t, "init", "--state", st, "--endpoint", "x"); err == nil {
		t.Fatal("second init without --force should fail")
	}

	// Flags may come after the name.
	mustWgh(t, "add", "phone", "--state", st)
	mustWgh(t, "add", "--state", st, "--psk=false", "laptop")
	mustWgh(t, "add", "--state", st, "tablet")
	if _, err := wgh(t, "add", "--state", st, "phone"); err == nil {
		t.Fatal("duplicate name should fail")
	}
	if _, err := wgh(t, "add", "--state", st, "../evil"); err == nil {
		t.Fatal("unsafe name should fail")
	}

	mustWgh(t, "remove", "--state", st, "laptop")
	mustWgh(t, "add", "--state", st, "desktop") // should reuse .3
	mustWgh(t, "add", "--state", st, "--ip", "10.44.0.200", "router")
	if _, err := wgh(t, "add", "--state", st, "--ip", "10.44.0.200", "dup-ip"); err == nil {
		t.Fatal("duplicate --ip should fail")
	}

	s, err := state.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"phone": "10.44.0.2", "desktop": "10.44.0.3", "tablet": "10.44.0.4", "router": "10.44.0.200"}
	if len(s.Peers) != len(want) {
		t.Fatalf("got %d peers, want %d", len(s.Peers), len(want))
	}
	for _, p := range s.Peers {
		if want[p.Name] != p.Address {
			t.Errorf("%s at %s, want %s", p.Name, p.Address, want[p.Name])
		}
	}
	if p, _ := s.Find("phone"); p.PresharedKey == "" {
		t.Error("phone should have a PSK by default")
	}

	list := mustWgh(t, "list", "--state", st)
	for name := range want {
		if !strings.Contains(list, name) {
			t.Errorf("list missing %s:\n%s", name, list)
		}
	}

	client := mustWgh(t, "show", "--state", st, "phone")
	for _, line := range []string{"Address = 10.44.0.2/24", "Endpoint = home.example.net:51820", "DNS = 10.44.0.1", "PresharedKey = "} {
		if !strings.Contains(client, line) {
			t.Errorf("client config missing %q:\n%s", line, client)
		}
	}

	qr := mustWgh(t, "qr", "--state", st, "phone", "--png", filepath.Join(dir, "phone.png"))
	if !strings.Contains(qr, "█") && !strings.Contains(qr, "▀") {
		t.Errorf("qr output does not look like a QR code:\n%s", qr)
	}

	out := filepath.Join(dir, "out")
	mustWgh(t, "export", "--state", st, "--dir", out, "--qr")
	srv, err := os.ReadFile(filepath.Join(out, "wg0.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(srv), "[Peer]"); got != 4 {
		t.Errorf("server config has %d peers, want 4", got)
	}

	// Everything holding a private key must be owner-only.
	for _, f := range []string{
		st,
		filepath.Join(dir, "phone.png"),
		filepath.Join(out, "wg0.conf"),
		filepath.Join(out, "peers", "phone.conf"),
		filepath.Join(out, "peers", "phone.png"),
	} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", f, fi.Mode().Perm())
		}
	}
}

func TestNotInitialised(t *testing.T) {
	st := filepath.Join(t.TempDir(), "state.json")
	_, err := wgh(t, "list", "--state", st)
	if err == nil || !strings.Contains(err.Error(), "wgh init") {
		t.Fatalf("err = %v, want hint to run init", err)
	}
}
