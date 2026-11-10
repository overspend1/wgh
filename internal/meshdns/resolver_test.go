package meshdns

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

type fakeRun struct {
	mu   sync.Mutex
	cmds []string
	fail string // fail any command starting with this
}

func (f *fakeRun) run(_ []byte, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, cmd)
	if f.fail != "" && strings.HasPrefix(cmd, f.fail) {
		return nil, errors.New("exit status 1")
	}
	return nil, nil
}

func (f *fakeRun) got() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.cmds, "\n")
}

func TestConfigure(t *testing.T) {
	f := &fakeRun{}
	if err := Configure(f.run, "wgh0", netip.MustParseAddr("10.144.0.2"), "wgh"); err != nil {
		t.Fatal(err)
	}
	want := "resolvectl dns wgh0 10.144.0.2\nresolvectl domain wgh0 wgh\nresolvectl default-route wgh0 false"
	if f.got() != want {
		t.Fatalf("commands:\n%s\nwant:\n%s", f.got(), want)
	}
	f = &fakeRun{}
	if err := Unconfigure(f.run, "wgh0"); err != nil || f.got() != "resolvectl revert wgh0" {
		t.Fatalf("unconfigure: %v\n%s", err, f.got())
	}
}

func TestConfigureFailureReverts(t *testing.T) {
	f := &fakeRun{fail: "resolvectl domain"}
	err := Configure(f.run, "wgh0", netip.MustParseAddr("10.144.0.2"), "wgh")
	if err == nil {
		t.Fatal("failure not reported")
	}
	want := "resolvectl dns wgh0 10.144.0.2\nresolvectl domain wgh0 wgh\nresolvectl revert wgh0"
	if f.got() != want {
		t.Fatalf("commands:\n%s\nwant:\n%s", f.got(), want)
	}
}

func TestAvailable(t *testing.T) {
	old := lookPath
	t.Cleanup(func() { lookPath = old })

	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	f := &fakeRun{}
	if Available(f.run) || f.got() != "" {
		t.Fatalf("available without resolvectl; ran %q", f.got())
	}
	lookPath = func(string) (string, error) { return "/usr/bin/resolvectl", nil }
	if !Available(f.run) || f.got() != "resolvectl status" {
		t.Fatalf("not available; ran %q", f.got())
	}
	f = &fakeRun{fail: "resolvectl status"}
	if Available(f.run) {
		t.Fatal("available while resolved is down")
	}
}
