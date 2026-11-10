package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")
	s := &State{
		Server: Server{Interface: "wg0", Subnet: "10.8.0.0/24", Address: "10.8.0.1", ListenPort: 51820, Endpoint: "x"},
		Peers:  []Peer{{Name: "phone", Address: "10.8.0.2"}},
	}
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("state file mode = %o, want 600", mode)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := di.Mode().Perm(); mode != 0o700 {
		t.Errorf("state dir mode = %o, want 700", mode)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != Version || len(got.Peers) != 1 || got.Peers[0].Name != "phone" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("want only state.json in dir, got %d entries", len(entries))
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("err = %v, want ErrNotInitialized", err)
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"phone", "wiktor-laptop", "pve1.lan", "a_b"} {
		if err := ValidName(ok); err != nil {
			t.Errorf("ValidName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../etc", "a/b", "-x", ".hidden", "has space"} {
		if ValidName(bad) == nil {
			t.Errorf("ValidName(%q) succeeded, want error", bad)
		}
	}
}

func TestRemoveAndSort(t *testing.T) {
	s := &State{Peers: []Peer{
		{Name: "c", Address: "10.8.0.10"},
		{Name: "a", Address: "10.8.0.2"},
		{Name: "b", Address: "10.8.0.9"},
	}}
	s.SortPeers()
	if s.Peers[0].Name != "a" || s.Peers[1].Name != "b" || s.Peers[2].Name != "c" {
		t.Fatalf("sort by address failed: %+v", s.Peers)
	}
	if err := s.Remove("b"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("b"); err == nil {
		t.Fatal("second remove should fail")
	}
	if len(s.Peers) != 2 {
		t.Fatalf("len = %d, want 2", len(s.Peers))
	}
}
