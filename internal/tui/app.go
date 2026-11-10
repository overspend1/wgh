package tui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/overspend1/wgh/internal/agent"
	"github.com/overspend1/wgh/internal/app"
	"github.com/overspend1/wgh/internal/coord"
	"github.com/overspend1/wgh/internal/mesh"
	"github.com/overspend1/wgh/internal/state"
	"github.com/overspend1/wgh/internal/update"
)

// AgentAPI is what the Devices tab needs from a running 'wgh up'.
type AgentAPI interface {
	Status() (agent.Status, error)
	SetExit(name string) (agent.Status, error)
	Rotate() (agent.Status, error)
}

// AdminAPI is what the Admin tab needs from a running 'wgh serve'.
type AdminAPI interface {
	Status() (coord.Status, error)
	Token(coord.TokenRequest) (string, error)
	Remove(name string) error
	Approve(name string) ([]string, bool, error)
	AddPhone(name string, exit bool) (string, error)
	PhoneConfig(name string) (string, error)
}

type tab int

const (
	tabWelcome tab = iota
	tabDevices
	tabAdmin
	tabSimple
)

func (t tab) String() string {
	return [...]string{"Start", "Devices", "Admin", "Simple server"}[t]
}

type modalKind int

const (
	modalNone modalKind = iota
	modalConfirm
	modalInput
	modalText
	modalQR
)

type modal struct {
	kind    modalKind
	title   string
	body    string
	input   textinput.Model
	input2  textinput.Model
	two     bool
	focus2  bool
	onYes   func() tea.Cmd
	onInput func(a, b string) tea.Cmd
}

type tickMsg struct{}
type devMsg struct {
	s   agent.Status
	err error
}
type admMsg struct {
	s   coord.Status
	err error
}
type doneMsg struct {
	ok  string
	err error
	// optional follow-up modal
	qrTitle, qr  string
	textTitle    string
	text         string
	refreshAfter bool
}

// App is the whole interface: tabs for this device, the coordinator and
// the simple server. Exported for tests.
type App struct {
	o             Options
	tabs          []tab
	cur           int
	width, height int

	agentAPI   AgentAPI
	adminAPI   AdminAPI
	agentState *agent.State
	dev        *agent.Status
	devErr     error
	devSel     int

	adm    *coord.Status
	admErr error
	admSel int

	classic *Model
	welSel  int

	m        modal
	msg      string
	msgIsErr bool
	latest   string
}

// NewApp works out which tabs to show and builds the first screen.
func NewApp(o Options) (*App, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.AgentState == "" {
		o.AgentState = agent.DefaultPath()
	}
	a := &App{o: o, width: 80, height: 24, agentAPI: o.Agent, adminAPI: o.Admin}
	if st, err := agent.Load(o.AgentState); err == nil {
		a.agentState = st
	}
	if a.agentAPI == nil {
		if a.agentState != nil || exists(agent.SocketPath(o.AgentState)) {
			a.agentAPI = agent.NewLocal(agent.SocketPath(o.AgentState))
		}
	}
	if a.adminAPI == nil && o.CoordDir != "" && exists(filepath.Join(o.CoordDir, "admin.sock")) {
		a.adminAPI = coord.NewAdmin(filepath.Join(o.CoordDir, "admin.sock"))
	}
	if a.agentAPI != nil {
		a.tabs = append(a.tabs, tabDevices)
	}
	if a.adminAPI != nil {
		a.tabs = append(a.tabs, tabAdmin)
	}
	if _, err := state.Load(o.StatePath); err == nil {
		if err := a.openClassic(); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, state.ErrNotInitialized) {
		return nil, err
	}
	if len(a.tabs) == 0 {
		a.tabs = []tab{tabWelcome}
	}
	return a, nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (a *App) openClassic() error {
	m, err := New(a.o)
	if err != nil {
		return err
	}
	a.classic = m
	a.classic.Update(tea.WindowSizeMsg{Width: a.width, Height: a.height - 2})
	for _, t := range a.tabs {
		if t == tabSimple {
			return nil
		}
	}
	a.tabs = append(a.tabs, tabSimple)
	return nil
}

func (a *App) tab() tab { return a.tabs[a.cur] }

// Tab names the open tab, for tests.
func (a *App) Tab() string { return a.tab().String() }

// Message is the status line, for tests.
func (a *App) Message() string { return a.msg }

// Init starts the refresh loop and the update check.
func (a *App) Init() tea.Cmd {
	cmds := []tea.Cmd{a.refresh(), tick()}
	if a.o.CheckUpdates && update.IsRelease(a.o.Version) {
		c := a.o.Updater
		if c == nil {
			c = update.Default()
		}
		cmds = append(cmds, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tag, err := c.Latest(ctx)
			if err != nil {
				return nil
			}
			return updateMsg{tag: tag}
		})
	}
	return tea.Batch(cmds...)
}

func tick() tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

func (a *App) refresh() tea.Cmd {
	var cmds []tea.Cmd
	if api := a.agentAPI; api != nil {
		cmds = append(cmds, func() tea.Msg { s, err := api.Status(); return devMsg{s, err} })
	}
	if api := a.adminAPI; api != nil {
		cmds = append(cmds, func() tea.Msg { s, err := api.Status(); return admMsg{s, err} })
	}
	return tea.Batch(cmds...)
}

func (a *App) setMsg(s string, isErr bool) { a.msg, a.msgIsErr = s, isErr }

// Update handles one event.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		if a.classic != nil {
			a.classic.Update(tea.WindowSizeMsg{Width: msg.Width, Height: msg.Height - 2})
		}
		return a, nil
	case tickMsg:
		return a, tea.Batch(a.refresh(), tick())
	case devMsg:
		if msg.err != nil {
			a.devErr = msg.err
		} else {
			a.dev, a.devErr = &msg.s, nil
		}
		a.devSel = clamp(a.devSel, a.devCount())
		return a, nil
	case admMsg:
		if msg.err != nil {
			a.admErr = msg.err
		} else {
			a.adm, a.admErr = &msg.s, nil
		}
		a.admSel = clamp(a.admSel, a.admCount())
		return a, nil
	case updateMsg:
		if update.Newer(a.o.Version, msg.tag) {
			a.latest = msg.tag
		}
		return a, nil
	case doneMsg:
		if msg.err != nil {
			a.setMsg(msg.err.Error(), true)
		} else if msg.ok != "" {
			a.setMsg(msg.ok, false)
		}
		if msg.qr != "" {
			a.m = modal{kind: modalQR, title: msg.qrTitle, body: msg.qr}
		} else if msg.text != "" {
			a.m = modal{kind: modalText, title: msg.textTitle, body: msg.text}
		}
		if msg.refreshAfter {
			return a, a.refresh()
		}
		return a, nil
	case joinedMsg:
		a.agentState = msg.st
		if a.agentAPI == nil {
			a.agentAPI = agent.NewLocal(agent.SocketPath(a.o.AgentState))
		}
		a.addTab(tabDevices)
		a.setMsg("joined as "+msg.st.Name, false)
		a.m = modal{kind: modalText, title: "Joined as " + msg.st.Name,
			body: value.Render("Address "+msg.st.Address+" in "+msg.st.Subnet+".") + "\n\n" +
				value.Render("Now connect it (this needs root):") + "\n\n  " + keyStyle.Render(msg.next) + "\n\n" +
				hint.Render("Leave it running, or install the systemd unit from the README.")}
		return a, a.refresh()
	case tea.KeyMsg:
		return a.key(msg)
	}
	if a.tab() == tabSimple && a.classic != nil {
		_, cmd := a.classic.Update(msg)
		return a, cmd
	}
	return a, nil
}

func clamp(i, n int) int {
	if i >= n {
		i = n - 1
	}
	if i < 0 {
		i = 0
	}
	return i
}

func (a *App) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.String() == "ctrl+c" {
		return a, tea.Quit
	}
	if a.m.kind != modalNone {
		return a.modalKey(k)
	}
	// The simple server keeps its own keys while a form or viewer is open.
	if a.tab() == tabSimple && a.classic != nil && a.classic.screen != screenList {
		if a.classic.screen == screenInit && a.classic.st == nil && k.String() == "esc" {
			a.classic = nil
			a.dropTab(tabSimple)
			return a, nil
		}
		_, cmd := a.classic.Update(k)
		if a.classic.st != nil && a.classic.screen == screenList {
			a.setMsg(a.classic.msg, a.classic.msgIsErr)
		}
		return a, cmd
	}
	switch k.String() {
	case "q":
		return a, tea.Quit
	case "tab", "right", "l":
		if len(a.tabs) > 1 {
			a.cur = (a.cur + 1) % len(a.tabs)
			a.setMsg("", false)
		}
		return a, nil
	case "shift+tab", "left", "h":
		if len(a.tabs) > 1 {
			a.cur = (a.cur + len(a.tabs) - 1) % len(a.tabs)
			a.setMsg("", false)
		}
		return a, nil
	case "1", "2", "3", "4":
		if i := int(k.String()[0] - '1'); i < len(a.tabs) {
			a.cur = i
			a.setMsg("", false)
		}
		return a, nil
	case "?":
		a.m = modal{kind: modalText, title: "Keys", body: helpFor(a.tab())}
		return a, nil
	}
	switch a.tab() {
	case tabWelcome:
		return a.welcomeKey(k)
	case tabDevices:
		return a.devKey(k)
	case tabAdmin:
		return a.admKey(k)
	case tabSimple:
		if k.String() == "esc" {
			return a, tea.Quit
		}
		_, cmd := a.classic.Update(k)
		a.msg, a.msgIsErr = a.classic.msg, a.classic.msgIsErr
		return a, cmd
	}
	return a, nil
}

func (a *App) dropTab(t tab) {
	for i, x := range a.tabs {
		if x == t {
			a.tabs = append(a.tabs[:i], a.tabs[i+1:]...)
			break
		}
	}
	if len(a.tabs) == 0 {
		a.tabs = []tab{tabWelcome}
	}
	a.cur = clamp(a.cur, len(a.tabs))
}

func (a *App) addTab(t tab) {
	for i, x := range a.tabs {
		if x == t {
			a.cur = i
			return
		}
	}
	// Welcome goes away once there is something real to show.
	if len(a.tabs) == 1 && a.tabs[0] == tabWelcome {
		a.tabs = nil
	}
	a.tabs = append(a.tabs, t)
	a.cur = len(a.tabs) - 1
}

// ---- modals ----

func newField(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.Prompt = "› "
	ti.PromptStyle = focusedPrompt
	ti.CharLimit = 4096
	ti.Width = 60
	return ti
}

func (a *App) ask(title, body string, yes func() tea.Cmd) {
	a.m = modal{kind: modalConfirm, title: title, body: body, onYes: yes}
}

func (a *App) prompt(title, body, placeholder string, f func(v, v2 string) tea.Cmd) {
	in := newField(placeholder)
	in.Focus()
	a.m = modal{kind: modalInput, title: title, body: body, input: in, onInput: f}
}

func (a *App) modalKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch a.m.kind {
	case modalConfirm:
		switch k.String() {
		case "y", "Y", "enter":
			f := a.m.onYes
			a.m = modal{}
			return a, f()
		case "n", "N", "esc", "q":
			a.m = modal{}
		}
		return a, nil
	case modalInput:
		switch k.String() {
		case "esc":
			a.m = modal{}
			return a, nil
		case "tab", "shift+tab", "down", "up":
			if a.m.two {
				a.m.focus2 = !a.m.focus2
				if a.m.focus2 {
					a.m.input.Blur()
					a.m.input2.Focus()
				} else {
					a.m.input2.Blur()
					a.m.input.Focus()
				}
			}
			return a, nil
		case "enter":
			if a.m.two && !a.m.focus2 {
				a.m.focus2 = true
				a.m.input.Blur()
				a.m.input2.Focus()
				return a, nil
			}
			f, v, v2 := a.m.onInput, strings.TrimSpace(a.m.input.Value()), strings.TrimSpace(a.m.input2.Value())
			a.m = modal{}
			return a, f(v, v2)
		}
		var cmd tea.Cmd
		if a.m.focus2 {
			a.m.input2, cmd = a.m.input2.Update(k)
		} else {
			a.m.input, cmd = a.m.input.Update(k)
		}
		return a, cmd
	default:
		if k.String() == "esc" || k.String() == "q" || k.String() == "enter" {
			a.m = modal{}
		}
		return a, nil
	}
}

// ---- welcome ----

var welcomeItems = []struct{ title, sub string }{
	{"Join a mesh", "paste a token from 'wgh admin token' on your coordinator"},
	{"Run a coordinator", "how to start your own server (a VPS or a box at home)"},
	{"Simple server", "make WireGuard configs and QR codes, nothing else"},
}

func (a *App) welcomeKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "up", "k":
		a.welSel = clamp(a.welSel-1, len(welcomeItems))
	case "down", "j":
		a.welSel = clamp(a.welSel+1, len(welcomeItems))
	case "esc":
		return a, tea.Quit
	case "enter", " ":
		switch a.welSel {
		case 0:
			a.openJoin()
		case 1:
			a.m = modal{kind: modalText, title: "Run a coordinator", body: coordinatorHelp}
		case 2:
			if err := a.openClassic(); err != nil {
				a.setMsg(err.Error(), true)
				return a, nil
			}
			a.addTab(tabSimple)
		}
	}
	return a, nil
}

func (a *App) openJoin() {
	a.prompt("Join a mesh", "The token comes from 'wgh admin token' on the coordinator.", "wgh1_…", nil)
	h, _ := os.Hostname()
	a.m.input2 = newField(agentName(h))
	a.m.two = true
	statePath := a.o.AgentState
	a.m.onInput = func(tok, name string) tea.Cmd {
		if name == "" {
			name = agentName(h)
		}
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			st, err := agent.Join(ctx, statePath, agent.JoinOptions{Token: tok, Name: name, Version: a.o.Version})
			if err != nil {
				return doneMsg{err: err}
			}
			next := "sudo wgh up"
			if os.Geteuid() != 0 {
				next = "sudo wgh up --state " + statePath
			}
			return joinedMsg{st: st, next: next}
		}
	}
}

type joinedMsg struct {
	st   *agent.State
	next string
}

// ---- devices ----

func (a *App) devCount() int {
	if a.dev == nil {
		return 0
	}
	return len(a.dev.Peers)
}

func (a *App) devSelected() *agent.PeerStatus {
	if a.dev == nil || a.devSel >= len(a.dev.Peers) {
		return nil
	}
	return &a.dev.Peers[a.devSel]
}

func (a *App) devKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	api := a.agentAPI
	switch k.String() {
	case "up", "k":
		a.devSel = clamp(a.devSel-1, a.devCount())
	case "down", "j":
		a.devSel = clamp(a.devSel+1, a.devCount())
	case "r":
		return a, a.refresh()
	case "x", "e":
		p := a.devSelected()
		if p == nil {
			return a, nil
		}
		if !p.Exit {
			a.setMsg(p.Name+" doesn't offer an exit node", true)
			return a, nil
		}
		name := p.Name
		return a, func() tea.Msg {
			s, err := api.SetExit(name)
			if err != nil {
				return doneMsg{err: err}
			}
			if s.ExitActive {
				return doneMsg{ok: "internet traffic now goes through " + name, refreshAfter: true}
			}
			return doneMsg{ok: "exit node " + name + ": " + s.ExitNote, refreshAfter: true}
		}
	case "X", "o":
		return a, func() tea.Msg {
			if _, err := api.SetExit(""); err != nil {
				return doneMsg{err: err}
			}
			return doneMsg{ok: "exit node off", refreshAfter: true}
		}
	case "R":
		a.ask("Switch to a new WireGuard key?", "The other devices pick it up within seconds;\nconnections drop for a moment.", func() tea.Cmd {
			return func() tea.Msg {
				if _, err := api.Rotate(); err != nil {
					return doneMsg{err: err}
				}
				return doneMsg{ok: "new key in use", refreshAfter: true}
			}
		})
	case "esc":
		return a, tea.Quit
	}
	return a, nil
}

// ---- admin ----

func (a *App) admCount() int {
	if a.adm == nil {
		return 0
	}
	return len(a.adm.Devices)
}

func (a *App) admKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	api := a.adminAPI
	var sel string
	var static bool
	if a.adm != nil && a.admSel < len(a.adm.Devices) {
		sel, static = a.adm.Devices[a.admSel].Name, a.adm.Devices[a.admSel].Static
	}
	switch k.String() {
	case "up", "k":
		a.admSel = clamp(a.admSel-1, a.admCount())
	case "down", "j":
		a.admSel = clamp(a.admSel+1, a.admCount())
	case "r":
		return a, a.refresh()
	case "t", "n":
		return a, func() tea.Msg {
			tok, err := api.Token(coord.TokenRequest{TTL: "1h"})
			if err != nil {
				return doneMsg{err: err}
			}
			return doneMsg{ok: "join token made (one use, 1 hour)", textTitle: "Join token",
				text: "On the new device run:\n\n" + keyStyle.Render(wrapToken("sudo wgh join "+tok, a.width-6)) + "\n\n" +
					hint.Render("It works once, for an hour. Anyone with it can join, so send it privately.")}
		}
	case "p":
		a.prompt("Add a phone", "For the WireGuard app on a phone, tablet or router. It reaches the\nmesh through the relay.", "phone", func(name, _ string) tea.Cmd {
			if name == "" {
				name = "phone"
			}
			return func() tea.Msg {
				conf, err := api.AddPhone(name, false)
				if err != nil {
					return doneMsg{err: err}
				}
				qr, err := app.QRTerminal(conf, false)
				if err != nil {
					return doneMsg{err: err}
				}
				return doneMsg{ok: "added " + name, qrTitle: "Scan with the WireGuard app: " + name, qr: strings.TrimRight(qr, "\n"), refreshAfter: true}
			}
		})
	case "enter", "c":
		if sel == "" || !static {
			return a, nil
		}
		return a, func() tea.Msg {
			conf, err := api.PhoneConfig(sel)
			if err != nil {
				return doneMsg{err: err}
			}
			qr, err := app.QRTerminal(conf, false)
			if err != nil {
				return doneMsg{err: err}
			}
			return doneMsg{qrTitle: "Scan with the WireGuard app: " + sel, qr: strings.TrimRight(qr, "\n")}
		}
	case "a":
		if sel == "" {
			return a, nil
		}
		d := a.adm.Devices[a.admSel]
		if len(d.PendingRoutes) == 0 && !d.PendingExit {
			a.setMsg(sel+" has nothing waiting for approval", false)
			return a, nil
		}
		what := strings.Join(d.PendingRoutes, ", ")
		if d.PendingExit {
			what = strings.TrimPrefix(what+", exit node", ", ")
		}
		a.ask("Approve "+sel+"?", "It shares: "+what+"\nOther devices will send that traffic through it.", func() tea.Cmd {
			return func() tea.Msg {
				if _, _, err := api.Approve(sel); err != nil {
					return doneMsg{err: err}
				}
				return doneMsg{ok: "approved " + sel, refreshAfter: true}
			}
		})
	case "d", "x", "delete":
		if sel == "" {
			return a, nil
		}
		a.ask("Remove "+sel+"?", "Its key stops working at once and the other devices drop it.\nTo bring it back it has to join again.", func() tea.Cmd {
			return func() tea.Msg {
				if err := api.Remove(sel); err != nil {
					return doneMsg{err: err}
				}
				return doneMsg{ok: "removed " + sel, refreshAfter: true}
			}
		})
	case "esc":
		return a, tea.Quit
	}
	return a, nil
}

func agentName(h string) string { return mesh.CleanName(h) }

// wrapToken breaks a long command over lines only when the window is too
// narrow to show it whole.
func wrapToken(s string, width int) string {
	if width < 20 || len(s) <= width {
		return s
	}
	var lines []string
	for len(s) > width {
		lines = append(lines, s[:width])
		s = s[width:]
	}
	return strings.Join(append(lines, s), "\n") + "\n" + hint.Render("(one line: widen the window to copy it in one go)")
}
