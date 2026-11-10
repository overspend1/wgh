package tui

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/overspend1/wgh/internal/agent"
	"github.com/overspend1/wgh/internal/coord"
	"github.com/overspend1/wgh/internal/mesh"
)

type fakeAgent struct {
	st      agent.Status
	exit    []string
	rotated int
}

func (f *fakeAgent) Status() (agent.Status, error) { return f.st, nil }
func (f *fakeAgent) SetExit(name string) (agent.Status, error) {
	f.exit = append(f.exit, name)
	f.st.ExitNode, f.st.ExitActive = name, name != ""
	return f.st, nil
}
func (f *fakeAgent) Rotate() (agent.Status, error) { f.rotated++; return f.st, nil }

type fakeAdmin struct {
	st       coord.Status
	removed  []string
	approved []string
	phones   []string
	tokens   int
}

func (f *fakeAdmin) Status() (coord.Status, error) { return f.st, nil }
func (f *fakeAdmin) Token(coord.TokenRequest) (string, error) {
	f.tokens++
	return "wgh1_TESTTOKEN", nil
}
func (f *fakeAdmin) Remove(name string) error {
	for i, d := range f.st.Devices {
		if d.Name == name {
			f.removed = append(f.removed, name)
			f.st.Devices = append(f.st.Devices[:i], f.st.Devices[i+1:]...)
			return nil
		}
	}
	return errors.New("no device named " + name)
}
func (f *fakeAdmin) Approve(name string) ([]string, bool, error) {
	f.approved = append(f.approved, name)
	return nil, false, nil
}
func (f *fakeAdmin) AddPhone(name string, exit bool) (string, error) {
	f.phones = append(f.phones, name)
	return "[Interface]\nPrivateKey = x\n", nil
}
func (f *fakeAdmin) PhoneConfig(name string) (string, error) { return "[Interface]\n", nil }

// do runs a command and feeds what it returns back into the app, without
// waiting on timers.
func do(a *App, cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	var msg tea.Msg
	select {
	case msg = <-ch:
	case <-time.After(500 * time.Millisecond):
		return // a timer; tests don't need it
	}
	switch m := msg.(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range m {
			do(a, c)
		}
	default:
		_, next := a.Update(m)
		do(a, next)
	}
}

func press(a *App, keys ...string) {
	for _, k := range keys {
		_, cmd := a.Update(key(k))
		do(a, cmd)
	}
}

func testApp(t *testing.T, ag AgentAPI, ad AdminAPI) *App {
	t.Helper()
	dir := t.TempDir()
	a, err := NewApp(Options{StatePath: filepath.Join(dir, "state.json"), AgentState: filepath.Join(dir, "agent.json"),
		Agent: ag, Admin: ad, Version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	a.Update(tea.WindowSizeMsg{Width: 110, Height: 30})
	do(a, a.refresh())
	return a
}

func TestAppWelcomeWithNothingSetUp(t *testing.T) {
	a := testApp(t, nil, nil)
	if a.Tab() != "Start" {
		t.Fatalf("tab = %q", a.Tab())
	}
	if v := a.View(); !strings.Contains(v, "Join a mesh") || !strings.Contains(v, "Run a coordinator") {
		t.Fatalf("welcome missing items:\n%s", v)
	}
	press(a, "down", "enter")
	if v := a.View(); !strings.Contains(v, "wgh serve --endpoint") {
		t.Fatalf("coordinator help not shown:\n%s", v)
	}
	press(a, "esc", "down", "enter")
	if a.Tab() != "Simple server" {
		t.Fatalf("simple server not opened, tab = %q", a.Tab())
	}
	press(a, "esc")
	if a.Tab() != "Start" {
		t.Fatalf("esc from an empty simple server should go back, tab = %q", a.Tab())
	}
}

func TestAppDevicesExitAndRotate(t *testing.T) {
	now := time.Now()
	ag := &fakeAgent{st: agent.Status{Name: "laptop", Address: "10.144.0.2", Subnet: mesh.DefaultSubnet, Connected: true,
		Peers: []agent.PeerStatus{
			{Name: "pve1", Address: "10.144.0.3", Online: true, Path: "direct", Endpoint: "192.168.1.20:41820",
				LastHandshake: now.Add(-5 * time.Second), RxBytes: 2048, TxBytes: 1 << 20, Exit: true},
			{Name: "nas", Address: "10.144.0.4", Path: "offline"},
		}}}
	a := testApp(t, ag, nil)
	if a.Tab() != "Devices" {
		t.Fatalf("tab = %q", a.Tab())
	}
	v := a.View()
	for _, want := range []string{"pve1", "10.144.0.3", "direct", "192.168.1.20:41820", "1.0 MiB", "nas"} {
		if !strings.Contains(v, want) {
			t.Errorf("devices view missing %q:\n%s", want, v)
		}
	}
	press(a, "x")
	if len(ag.exit) != 1 || ag.exit[0] != "pve1" || !strings.Contains(a.Message(), "pve1") {
		t.Fatalf("exit = %v, msg %q", ag.exit, a.Message())
	}
	press(a, "j", "x")
	if len(ag.exit) != 1 || !strings.Contains(a.Message(), "doesn't offer") {
		t.Fatalf("nas is no exit node: exit = %v, msg %q", ag.exit, a.Message())
	}
	press(a, "X")
	if ag.exit[len(ag.exit)-1] != "" {
		t.Fatalf("X should turn the exit node off: %v", ag.exit)
	}
	press(a, "R", "n")
	if ag.rotated != 0 {
		t.Fatal("rotate ran without a yes")
	}
	press(a, "R", "y")
	if ag.rotated != 1 {
		t.Fatal("rotate did not run after yes")
	}
}

func TestAppAdminApproveRemovePhoneToken(t *testing.T) {
	ad := &fakeAdmin{st: coord.Status{URL: "https://vpn.example.com:8443", Subnet: mesh.DefaultSubnet, Devices: []mesh.Node{
		{Name: "laptop", Address: "10.144.0.2", Online: true, OS: "linux"},
		{Name: "pve1", Address: "10.144.0.3", PendingRoutes: []string{"192.168.1.0/24"}},
	}}}
	a := testApp(t, nil, ad)
	if a.Tab() != "Admin" {
		t.Fatalf("tab = %q", a.Tab())
	}
	if v := a.View(); !strings.Contains(v, "needs approval") {
		t.Fatalf("pending route not flagged:\n%s", v)
	}
	press(a, "a")
	if len(ad.approved) != 0 || !strings.Contains(a.Message(), "nothing waiting") {
		t.Fatalf("laptop has nothing to approve: %v %q", ad.approved, a.Message())
	}
	press(a, "j", "a")
	if v := a.View(); !strings.Contains(v, "192.168.1.0/24") {
		t.Fatalf("approve confirm should name the route:\n%s", v)
	}
	press(a, "y")
	if len(ad.approved) != 1 || ad.approved[0] != "pve1" {
		t.Fatalf("approved = %v", ad.approved)
	}
	press(a, "d", "esc")
	if len(ad.removed) != 0 {
		t.Fatal("remove ran without a yes")
	}
	press(a, "d", "y")
	if len(ad.removed) != 1 || ad.removed[0] != "pve1" {
		t.Fatalf("removed = %v", ad.removed)
	}
	press(a, "t")
	if ad.tokens != 1 || !strings.Contains(a.View(), "wgh1_TESTTOKEN") {
		t.Fatalf("token not shown:\n%s", a.View())
	}
	press(a, "esc", "p")
	for _, r := range "pixel" {
		press(a, string(r))
	}
	press(a, "enter")
	if len(ad.phones) != 1 || ad.phones[0] != "pixel" {
		t.Fatalf("phones = %v", ad.phones)
	}
	if v := a.View(); !strings.Contains(v, "Scan with the WireGuard app") {
		t.Fatalf("QR not shown:\n%s", v)
	}
}

func TestAppTabsAndNarrowWindow(t *testing.T) {
	a := testApp(t, &fakeAgent{st: agent.Status{Name: "laptop", Connected: true}}, &fakeAdmin{})
	press(a, "tab")
	if a.Tab() != "Admin" {
		t.Fatalf("tab = %q", a.Tab())
	}
	press(a, "1")
	if a.Tab() != "Devices" {
		t.Fatalf("tab = %q", a.Tab())
	}
	press(a, "?")
	if !strings.Contains(a.View(), "Keys") {
		t.Fatal("help not shown")
	}
	press(a, "esc")
	for _, w := range []int{40, 60, 200} {
		a.Update(tea.WindowSizeMsg{Width: w, Height: 20})
		for i, line := range strings.Split(a.View(), "\n") {
			if n := lipgloss.Width(line); n > w {
				t.Errorf("width %d: line %d is %d wide", w, i, n)
			}
		}
	}
}
