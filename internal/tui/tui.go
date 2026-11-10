// Package tui is the full-screen interface opened by running wgh with no
// arguments. It uses the same operations as the subcommands and the same
// state file.
package tui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/overspend1/wgh/internal/app"
	"github.com/overspend1/wgh/internal/render"
	"github.com/overspend1/wgh/internal/state"
	"github.com/overspend1/wgh/internal/update"
)

type screen int

const (
	screenInit screen = iota
	screenList
	screenAdd
	screenRemove
	screenClient
	screenServer
	screenQR
	screenExport
	screenHelp
)

// Options configures the TUI.
type Options struct {
	StatePath    string
	Version      string
	CheckUpdates bool
	// Updater is used for the update check; nil means update.Default().
	Updater *update.Client
	// Now is used for peer timestamps; nil means time.Now.
	Now func() time.Time
}

// Run opens the TUI and blocks until the user quits.
func Run(o Options) error {
	m, err := New(o)
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

// field is one row of a form: a text input, or a yes/no toggle.
type field struct {
	label  string
	help   string
	input  textinput.Model
	toggle bool
	on     bool
}

type updateMsg struct{ tag string }

// Model is the Bubble Tea model. It is exported for tests.
type Model struct {
	opts   Options
	st     *state.State
	screen screen
	prev   screen

	width, height int

	table  table.Model
	form   []field
	focus  int
	vp     viewport.Model
	qrText string
	qrPeer string
	target string // peer name for remove/QR/config screens

	msg      string
	msgIsErr bool
	latest   string
}

// New loads the state (if any) and builds the first screen.
func New(o Options) (*Model, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	m := &Model{opts: o, width: 80, height: 24}
	m.table = newTable()
	st, err := state.Load(o.StatePath)
	switch {
	case errors.Is(err, state.ErrNotInitialized):
		m.openInit()
	case err != nil:
		return nil, err
	default:
		m.st = st
		m.screen = screenList
		m.refreshTable()
	}
	return m, nil
}

// Init starts the optional background update check.
func (m *Model) Init() tea.Cmd {
	if !m.opts.CheckUpdates || !update.IsRelease(m.opts.Version) {
		return nil
	}
	c := m.opts.Updater
	if c == nil {
		c = update.Default()
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tag, err := c.Latest(ctx)
		if err != nil {
			return nil // offline or no releases: say nothing
		}
		return updateMsg{tag: tag}
	}
}

// State returns the current state, for tests.
func (m *Model) State() *state.State { return m.st }

// Screen returns the screen shown, for tests.
func (m *Model) Screen() int { return int(m.screen) }

// Message returns the status line, for tests.
func (m *Model) Message() string { return m.msg }

// ---------------------------------------------------------------------------
// Update

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case updateMsg:
		if update.Newer(m.opts.Version, msg.tag) {
			m.latest = msg.tag
		}
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		switch m.screen {
		case screenInit, screenAdd, screenExport:
			return m.updateForm(msg)
		case screenList:
			return m.updateList(msg)
		case screenRemove:
			return m.updateRemove(msg)
		case screenClient, screenServer, screenHelp:
			return m.updateViewer(msg)
		case screenQR:
			return m.updateQR(msg)
		}
	}
	return m, nil
}

func (m *Model) setMsg(s string, isErr bool) { m.msg, m.msgIsErr = s, isErr }

func (m *Model) updateList(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.msg = ""
	switch k.String() {
	case "q", "esc":
		return m, tea.Quit
	case "a", "n":
		m.openAdd()
		return m, textinput.Blink
	case "d", "x", "delete":
		if p := m.selected(); p != nil {
			m.target = p.Name
			m.screen = screenRemove
		}
		return m, nil
	case "enter", "c":
		if p := m.selected(); p != nil {
			m.showClient(p)
		}
		return m, nil
	case "r":
		if p := m.selected(); p != nil {
			m.showQR(p)
		}
		return m, nil
	case "s":
		m.showServer()
		return m, nil
	case "e":
		m.openExport()
		return m, textinput.Blink
	case "?", "h":
		m.showHelp()
		return m, nil
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(k)
	return m, cmd
}

func (m *Model) updateRemove(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "y", "Y":
		if err := m.st.Remove(m.target); err != nil {
			m.setMsg(err.Error(), true)
		} else if err := state.Save(m.opts.StatePath, m.st); err != nil {
			m.setMsg(err.Error(), true)
		} else {
			m.setMsg(fmt.Sprintf("Removed %s. Export again and reload the server to revoke it.", m.target), false)
		}
		m.refreshTable()
		m.screen = screenList
	case "n", "N", "esc", "q":
		m.screen = screenList
	}
	return m, nil
}

func (m *Model) updateViewer(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc", "q", "backspace":
		m.screen = screenList
		return m, nil
	case "r":
		if m.screen == screenClient {
			if p, _ := m.st.Find(m.target); p != nil {
				m.showQR(p)
			}
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(k)
	return m, cmd
}

func (m *Model) updateQR(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc", "q", "backspace":
		m.screen = screenList
	case "c":
		if p, _ := m.st.Find(m.target); p != nil {
			m.showClient(p)
		}
	case "p":
		p, _ := m.st.Find(m.target)
		if p == nil {
			return m, nil
		}
		conf, err := render.Client(m.st, p)
		if err == nil {
			var img []byte
			if img, err = app.QRPNG(conf, 512); err == nil {
				path := p.Name + ".png"
				if err = state.WriteSecret(path, img); err == nil {
					abs, _ := filepath.Abs(path)
					m.setMsg("Saved "+abs+" (contains the private key)", false)
				}
			}
		}
		if err != nil {
			m.setMsg(err.Error(), true)
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Forms

func newInput(placeholder, val string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.SetValue(val)
	ti.Prompt = "› "
	ti.CharLimit = 256
	ti.Width = 40
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(brightRed)
	ti.PlaceholderStyle = hint
	ti.TextStyle = value
	return ti
}

func (m *Model) openInit() {
	d := app.DefaultInitOptions()
	m.form = []field{
		{label: "Endpoint", help: "public host or IP your devices dial", input: newInput("vpn.example.com", "")},
		{label: "Subnet", help: "tunnel subnet, blank for " + d.Subnet, input: newInput(d.Subnet, "")},
		{label: "Port", help: "UDP listen port", input: newInput(strconv.Itoa(d.Port), "")},
		{label: "Interface", help: "server interface name", input: newInput(d.Interface, "")},
		{label: "DNS", help: "optional, comma-separated, e.g. a Pi-hole", input: newInput("none", "")},
		{label: "NAT interface", help: "optional, adds iptables NAT rules, e.g. eth0", input: newInput("none", "")},
	}
	m.screen = screenInit
	m.focusField(0)
}

func (m *Model) openAdd() {
	d := app.DefaultPeerOptions()
	m.form = []field{
		{label: "Name", help: "letters, digits, . _ -", input: newInput("phone", "")},
		{label: "IP", help: "blank picks the next free address", input: newInput("auto", "")},
		{label: "Allowed IPs", help: "routes through the tunnel; blank is full tunnel", input: newInput(strings.Join(d.AllowedIPs, ", "), "")},
		{label: "DNS", help: "blank uses the server's DNS", input: newInput("server default", "")},
		{label: "Keepalive", help: "seconds, 0 disables", input: newInput(strconv.Itoa(d.Keepalive), "")},
		{label: "Preshared key", help: "space toggles", toggle: true, on: d.PSK},
	}
	m.screen = screenAdd
	m.focusField(0)
}

func (m *Model) openExport() {
	m.form = []field{
		{label: "Directory", help: "server and client configs go here", input: newInput(defaultExportDir, "")},
		{label: "QR PNGs", help: "space toggles", toggle: true, on: true},
	}
	m.screen = screenExport
	m.focusField(0)
}

func (m *Model) focusField(i int) {
	m.focus = i
	for j := range m.form {
		f := &m.form[j]
		if f.toggle {
			continue
		}
		if j == i {
			f.input.Focus()
			f.input.PromptStyle = focusedPrompt
		} else {
			f.input.Blur()
			f.input.PromptStyle = blurredPrompt
		}
	}
}

func (m *Model) updateForm(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		if m.screen == screenInit {
			return m, tea.Quit
		}
		m.msg = ""
		m.screen = screenList
		return m, nil
	case "tab", "down":
		m.focusField((m.focus + 1) % len(m.form))
		return m, nil
	case "shift+tab", "up":
		m.focusField((m.focus + len(m.form) - 1) % len(m.form))
		return m, nil
	case "ctrl+s":
		m.submit()
		return m, nil
	case "enter":
		if m.focus == len(m.form)-1 {
			m.submit()
		} else {
			m.focusField(m.focus + 1)
		}
		return m, nil
	}
	f := &m.form[m.focus]
	if f.toggle {
		if s := k.String(); s == " " || s == "space" || s == "y" || s == "n" {
			switch s {
			case "y":
				f.on = true
			case "n":
				f.on = false
			default:
				f.on = !f.on
			}
		}
		return m, nil
	}
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(k)
	return m, cmd
}

func (m *Model) val(i int) string { return strings.TrimSpace(m.form[i].input.Value()) }

// valOr returns field i, or its placeholder (the default) when left blank.
func (m *Model) valOr(i int) string {
	if v := m.val(i); v != "" {
		return v
	}
	return m.form[i].input.Placeholder
}

const defaultExportDir = "./wg-out"

func (m *Model) submit() {
	var err error
	switch m.screen {
	case screenInit:
		err = m.submitInit()
	case screenAdd:
		err = m.submitAdd()
	case screenExport:
		err = m.submitExport()
	}
	if err != nil {
		m.setMsg(err.Error(), true)
	}
}

func (m *Model) submitInit() error {
	port, err := strconv.Atoi(m.valOr(2))
	if err != nil {
		return fmt.Errorf("port %q is not a number", m.valOr(2))
	}
	st, err := app.NewServer(app.InitOptions{
		Endpoint:     m.val(0),
		Subnet:       m.valOr(1),
		Port:         port,
		Interface:    m.valOr(3),
		DNS:          render.SplitList(m.val(4)),
		NATInterface: m.val(5),
	})
	if err != nil {
		return err
	}
	if err := state.Save(m.opts.StatePath, st); err != nil {
		return err
	}
	m.st = st
	m.screen = screenList
	m.refreshTable()
	m.setMsg("Server created. Press a to add your first peer.", false)
	return nil
}

func (m *Model) submitAdd() error {
	keep, err := strconv.Atoi(m.valOr(4))
	if err != nil {
		return fmt.Errorf("keepalive %q is not a number", m.valOr(4))
	}
	p, err := app.AddPeer(m.st, app.PeerOptions{
		Name:       m.val(0),
		IP:         m.val(1),
		AllowedIPs: render.SplitList(m.valOr(2)),
		DNS:        render.SplitList(m.val(3)),
		Keepalive:  keep,
		PSK:        m.form[5].on,
	}, m.opts.Now())
	if err != nil {
		// AddPeer appends only on success, so the state is unchanged here.
		return err
	}
	if err := state.Save(m.opts.StatePath, m.st); err != nil {
		_ = m.st.Remove(p.Name)
		return err
	}
	m.refreshTable()
	m.selectPeer(p.Name)
	m.showQR(p)
	m.setMsg(fmt.Sprintf("Added %s at %s. Scan it now, or press esc.", p.Name, p.Address), false)
	return nil
}

func (m *Model) submitExport() error {
	dir := m.valOr(0)
	written, err := app.Export(m.st, dir, m.form[1].on)
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(dir)
	m.screen = screenList
	m.setMsg(fmt.Sprintf("Wrote %d files to %s", len(written), abs), false)
	return nil
}

// ---------------------------------------------------------------------------
// Peer table and viewers

func newTable() table.Model {
	t := table.New(table.WithFocused(true), table.WithColumns(columns(80)))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(red).
		BorderBottom(true).Bold(true).Foreground(brightRed)
	s.Selected = s.Selected.Foreground(white).Background(red).Bold(true)
	s.Cell = s.Cell.Foreground(text)
	t.SetStyles(s)
	return t
}

func columns(width int) []table.Column {
	key := width - 16 - 16 - 5 - 12 - 12
	if key < 12 {
		key = 12
	}
	if key > 44 {
		key = 44
	}
	return []table.Column{
		{Title: "Name", Width: 16},
		{Title: "Address", Width: 16},
		{Title: "PSK", Width: 5},
		{Title: "Public key", Width: key},
		{Title: "Created", Width: 10},
	}
}

func (m *Model) refreshTable() {
	if m.st == nil {
		return
	}
	rows := make([]table.Row, 0, len(m.st.Peers))
	for _, p := range m.st.Peers {
		psk := "no"
		if p.PresharedKey != "" {
			psk = "yes"
		}
		rows = append(rows, table.Row{p.Name, p.Address, psk, p.PublicKey, p.CreatedAt.Format("2006-01-02")})
	}
	m.table.SetRows(rows)
	if c := m.table.Cursor(); c >= len(rows) && len(rows) > 0 {
		m.table.SetCursor(len(rows) - 1)
	}
	m.layout()
}

func (m *Model) selected() *state.Peer {
	if m.st == nil || len(m.st.Peers) == 0 {
		return nil
	}
	row := m.table.SelectedRow()
	if row == nil {
		return nil
	}
	p, _ := m.st.Find(row[0])
	return p
}

func (m *Model) selectPeer(name string) {
	for i, p := range m.st.Peers {
		if p.Name == name {
			m.table.SetCursor(i)
		}
	}
}

func (m *Model) layout() {
	m.table.SetColumns(columns(m.width - 4))
	h := m.height - 9
	if h < 3 {
		h = 3
	}
	m.table.SetHeight(h)
	m.vp.Width = m.width - 4
	m.vp.Height = m.height - 7
}

func (m *Model) openViewer(s screen, content string) {
	m.vp = viewport.New(m.width-4, m.height-7)
	m.vp.SetContent(content)
	m.screen = s
}

func (m *Model) showClient(p *state.Peer) {
	conf, err := render.Client(m.st, p)
	if err != nil {
		m.setMsg(err.Error(), true)
		return
	}
	m.target = p.Name
	m.openViewer(screenClient, highlightConf(conf))
}

func (m *Model) showServer() {
	conf, err := render.Server(m.st)
	if err != nil {
		m.setMsg(err.Error(), true)
		return
	}
	m.openViewer(screenServer, highlightConf(conf))
}

func (m *Model) showQR(p *state.Peer) {
	conf, err := render.Client(m.st, p)
	if err != nil {
		m.setMsg(err.Error(), true)
		return
	}
	qr, err := app.QRTerminal(conf, false)
	if err != nil {
		m.setMsg(err.Error(), true)
		return
	}
	m.target = p.Name
	m.qrText = strings.TrimRight(qr, "\n")
	m.screen = screenQR
}

func (m *Model) showHelp() {
	m.openViewer(screenHelp, helpText)
}

// highlightConf colours section headers, keys and comments of a .conf file.
func highlightConf(conf string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(conf, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "["):
			b.WriteString(heading.Render(line))
		case strings.HasPrefix(line, "#"):
			b.WriteString(hint.Render(line))
		case strings.Contains(line, " = "):
			k, v, _ := strings.Cut(line, " = ")
			b.WriteString(keyStyle.Render(k) + label.Render(" = ") + value.Render(v))
		default:
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// View

func (m *Model) View() string {
	var body, keys string
	switch m.screen {
	case screenInit:
		body = m.viewForm("Set up your WireGuard server",
			"Nothing touches your network: wgh only writes files.")
		keys = keyHelp("tab", "next", "enter", "next / create", "esc", "quit")
	case screenAdd:
		body = m.viewForm("Add a peer", "Keys and the address are generated for you.")
		keys = keyHelp("tab", "next", "enter", "next / add", "esc", "cancel")
	case screenExport:
		body = m.viewForm("Export configs", "Every file is written with mode 0600.")
		keys = keyHelp("tab", "next", "enter", "next / export", "esc", "cancel")
	case screenList:
		body = m.viewList()
		keys = keyHelp("a", "add", "d", "remove", "enter", "config", "r", "QR", "s", "server", "e", "export", "?", "help", "q", "quit")
	case screenRemove:
		body = panel.Render(fmt.Sprintf("%s\n\n%s\n%s",
			heading.Render("Remove "+m.target+"?"),
			value.Render("Its keys are deleted from the state file."),
			hint.Render("Export again and reload the server afterwards.")))
		keys = keyHelp("y", "remove", "n", "keep")
	case screenClient:
		body = heading.Render("Client config: "+m.target) + "\n\n" + m.vp.View()
		keys = keyHelp("r", "QR code", "↑/↓", "scroll", "esc", "back")
	case screenServer:
		body = heading.Render("Server config: "+m.st.Server.Interface+".conf") + "\n\n" + m.vp.View()
		keys = keyHelp("↑/↓", "scroll", "esc", "back")
	case screenHelp:
		body = m.vp.View()
		keys = keyHelp("esc", "back")
	case screenQR:
		body = m.viewQR()
		keys = keyHelp("p", "save PNG", "c", "config", "esc", "back")
	}

	status := ""
	if m.msg != "" {
		if m.msgIsErr {
			status = errStyle.Render("✗ " + m.msg)
		} else {
			status = okStyle.Render("✓ " + m.msg)
		}
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		m.viewHeader(),
		"",
		lipgloss.NewStyle().Padding(0, 2).Render(body),
		"",
		lipgloss.NewStyle().Padding(0, 2).Render(status),
		lipgloss.NewStyle().Padding(0, 2).Render(keys),
	)
}

func (m *Model) viewHeader() string {
	left := titleBar.Render("wgh")
	info := ""
	if m.st != nil {
		s := m.st.Server
		peers := fmt.Sprintf("%d peers", len(m.st.Peers))
		if len(m.st.Peers) == 1 {
			peers = "1 peer"
		}
		info = fmt.Sprintf("%s  %s  %s  %s", s.Interface, s.Subnet,
			render.Endpoint(s.Endpoint, s.ListenPort), peers)
	}
	right := ""
	if m.latest != "" {
		right = badge.Render(m.latest + " available · run wgh update")
	} else if m.opts.Version != "" {
		right = infoBar.Render("v" + strings.TrimPrefix(m.opts.Version, "v"))
	}
	mid := infoBar.Render(info)
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(mid) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + mid + strings.Repeat(" ", gap) + right
}

func (m *Model) viewList() string {
	if len(m.st.Peers) == 0 {
		return panel.Render(heading.Render("No peers yet") + "\n\n" +
			value.Render("Press ") + keyStyle.Render("a") + value.Render(" to add one. It gets the next free address,") + "\n" +
			value.Render("its own keys and a QR code for the WireGuard app."))
	}
	return m.table.View()
}

func (m *Model) viewForm(title, sub string) string {
	var b strings.Builder
	b.WriteString(heading.Render(title) + "\n" + hint.Render(sub) + "\n\n")
	for i, f := range m.form {
		marker := "  "
		lbl := label
		if i == m.focus {
			marker = focusedPrompt.Render("▌ ")
			lbl = heading
		}
		b.WriteString(marker + lbl.Render(fmt.Sprintf("%-14s", f.label)))
		if f.toggle {
			box := "[ ] no"
			if f.on {
				box = "[x] yes"
			}
			st := value
			if i == m.focus {
				st = keyStyle
			}
			b.WriteString("  " + st.Render(box))
		} else {
			b.WriteString(f.input.View())
		}
		b.WriteString("\n" + "                " + hint.Render(f.help) + "\n")
	}
	return b.String()
}

func (m *Model) viewQR() string {
	qr := qrStyle.Render(m.qrText)
	title := heading.Render("Scan with the WireGuard app: "+m.target) + "\n" +
		hint.Render("It contains this peer's private key. Don't screenshot or share it.")
	need := lipgloss.Height(qr) + 9
	if m.height < need || m.width < lipgloss.Width(qr)+4 {
		return title + "\n\n" + errStyle.Render(fmt.Sprintf(
			"The window is too small for the QR code (needs %dx%d, have %dx%d).",
			lipgloss.Width(qr)+4, need, m.width, m.height)) + "\n" +
			value.Render("Make it bigger, zoom out, or press p to save a PNG.")
	}
	return title + "\n\n" + qr
}

func keyHelp(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, keyStyle.Render(pairs[i])+" "+hint.Render(pairs[i+1]))
	}
	return strings.Join(parts, hint.Render("  ·  "))
}

const helpText = `wgh keys

  a        add a peer (shows its QR code right away)
  d        remove the selected peer
  enter    show the selected peer's client config
  r        show the selected peer's QR code
  s        show the server config
  e        export the server and all client configs
  ↑/↓ j/k  move
  q        quit

The same actions work as subcommands for scripts:
  wgh add, list, remove, show, qr, server, export, update

After adding or removing a peer, export again and reload the
server, e.g. sudo systemctl restart wg-quick@wg0.
`
