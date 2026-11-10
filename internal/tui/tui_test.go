package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/overspend1/wgh/internal/state"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEscape}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "ctrl+s":
		return tea.KeyMsg{Type: tea.KeyCtrlS}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func send(t *testing.T, m *Model, keys ...string) {
	t.Helper()
	for _, k := range keys {
		m.Update(key(k))
	}
}

func typeText(t *testing.T, m *Model, s string) {
	t.Helper()
	for _, r := range s {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func newModel(t *testing.T) (*Model, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := New(Options{StatePath: path, Version: "0.2.0",
		Now: func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 60})
	return m, path
}

func TestInitAddRemoveFlow(t *testing.T) {
	m, path := newModel(t)
	if m.Screen() != int(screenInit) {
		t.Fatalf("no state file should open the setup form, got screen %d", m.Screen())
	}

	// Submitting without an endpoint shows an error and stays on the form.
	send(t, m, "ctrl+s")
	if m.Screen() != int(screenInit) || !strings.Contains(m.Message(), "endpoint") {
		t.Fatalf("want endpoint error, got screen %d msg %q", m.Screen(), m.Message())
	}

	typeText(t, m, "vpn.example.com")
	send(t, m, "ctrl+s")
	if m.Screen() != int(screenList) {
		t.Fatalf("after setup want list, got %d (%s)", m.Screen(), m.Message())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state not saved: %v", err)
	}
	if !strings.Contains(m.View(), "No peers yet") {
		t.Error("empty list should say there are no peers")
	}

	// Add "phone" with defaults: it lands on the QR screen.
	send(t, m, "a")
	typeText(t, m, "phone")
	send(t, m, "ctrl+s")
	if m.Screen() != int(screenQR) {
		t.Fatalf("after add want QR screen, got %d (%s)", m.Screen(), m.Message())
	}
	if !strings.Contains(m.View(), "▀") && !strings.Contains(m.View(), "█") {
		t.Error("QR screen shows no QR code")
	}
	send(t, m, "esc")

	// Add "laptop" without a PSK, by tabbing to the toggle and pressing space.
	send(t, m, "a")
	typeText(t, m, "laptop")
	send(t, m, "tab", "tab")
	typeText(t, m, "10.8.0.0/24, 192.168.1.0/24")
	send(t, m, "tab", "tab", "tab", "space", "enter")
	send(t, m, "esc")

	st, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Peers) != 2 {
		t.Fatalf("want 2 peers on disk, got %d", len(st.Peers))
	}
	phone, _ := st.Find("phone")
	laptop, _ := st.Find("laptop")
	if phone.Address != "10.8.0.2" || phone.PresharedKey == "" {
		t.Errorf("phone = %s psk=%t", phone.Address, phone.PresharedKey != "")
	}
	if laptop.Address != "10.8.0.3" || laptop.PresharedKey != "" {
		t.Errorf("laptop = %s psk=%t", laptop.Address, laptop.PresharedKey != "")
	}
	if strings.Join(laptop.AllowedIPs, ",") != "10.8.0.0/24,192.168.1.0/24" {
		t.Errorf("laptop allowed IPs = %v", laptop.AllowedIPs)
	}
	if strings.Join(phone.AllowedIPs, ",") != "0.0.0.0/0,::/0" || phone.Keepalive != 25 {
		t.Errorf("phone should get the defaults: %v keepalive %d", phone.AllowedIPs, phone.Keepalive)
	}

	// Duplicate names are refused and nothing changes.
	send(t, m, "a")
	typeText(t, m, "phone")
	send(t, m, "ctrl+s")
	if m.Screen() != int(screenAdd) || !strings.Contains(m.Message(), "already exists") {
		t.Fatalf("duplicate: screen %d msg %q", m.Screen(), m.Message())
	}
	send(t, m, "esc")

	// Remove the selected (second) peer after confirming.
	send(t, m, "down", "d")
	if m.Screen() != int(screenRemove) {
		t.Fatalf("want remove confirm, got %d", m.Screen())
	}
	send(t, m, "n")
	if len(m.State().Peers) != 2 {
		t.Fatal("'n' must not remove")
	}
	send(t, m, "d", "y")
	st, _ = state.Load(path)
	if len(st.Peers) != 1 || st.Peers[0].Name != "phone" {
		t.Fatalf("after remove, peers on disk = %+v", st.Peers)
	}
}

func TestViewersAndExport(t *testing.T) {
	m, _ := newModel(t)
	typeText(t, m, "vpn.example.com")
	send(t, m, "ctrl+s", "a")
	typeText(t, m, "phone")
	send(t, m, "ctrl+s", "esc")

	send(t, m, "enter")
	if m.Screen() != int(screenClient) || !strings.Contains(m.View(), "Endpoint") {
		t.Fatalf("client config view: screen %d", m.Screen())
	}
	send(t, m, "esc", "s")
	if m.Screen() != int(screenServer) || !strings.Contains(m.View(), "ListenPort") {
		t.Fatalf("server config view: screen %d", m.Screen())
	}
	send(t, m, "esc", "?")
	if m.Screen() != int(screenHelp) {
		t.Fatalf("help: screen %d", m.Screen())
	}
	send(t, m, "esc")

	out := filepath.Join(t.TempDir(), "out")
	send(t, m, "e")
	typeText(t, m, out)
	send(t, m, "ctrl+s")
	if m.Screen() != int(screenList) || !strings.Contains(m.Message(), "Wrote 3 files") {
		t.Fatalf("export: screen %d msg %q", m.Screen(), m.Message())
	}
	for _, f := range []string{"wg0.conf", "peers/phone.conf", "peers/phone.png"} {
		fi, err := os.Stat(filepath.Join(out, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o", f, fi.Mode().Perm())
		}
	}
}

func TestQRTooSmallWindow(t *testing.T) {
	m, _ := newModel(t)
	typeText(t, m, "vpn.example.com")
	send(t, m, "ctrl+s", "a")
	typeText(t, m, "phone")
	send(t, m, "ctrl+s")
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	if !strings.Contains(m.View(), "too small") {
		t.Fatal("a small window should explain why the QR code is hidden")
	}
}

func TestUpdateBadge(t *testing.T) {
	m, _ := newModel(t)
	m.Update(updateMsg{tag: "v0.1.0"})
	if strings.Contains(m.View(), "available") {
		t.Fatal("an older release must not show the badge")
	}
	m.Update(updateMsg{tag: "v0.3.0"})
	if !strings.Contains(m.View(), "v0.3.0 available") {
		t.Fatal("a newer release should show the badge")
	}
}
