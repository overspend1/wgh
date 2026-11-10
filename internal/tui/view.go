package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/overspend1/wgh/internal/agent"
	"github.com/overspend1/wgh/internal/app"
)

var (
	tabOn   = lipgloss.NewStyle().Bold(true).Foreground(white).Background(red).Padding(0, 1)
	tabOff  = lipgloss.NewStyle().Foreground(muted).Padding(0, 1)
	dotOn   = lipgloss.NewStyle().Foreground(okGreen)
	dotOff  = lipgloss.NewStyle().Foreground(muted)
	pathDir = lipgloss.NewStyle().Foreground(okGreen)
	pathRel = lipgloss.NewStyle().Foreground(brightRed)
	dim     = lipgloss.NewStyle().Foreground(muted)
)

// View draws the whole screen.
func (a *App) View() string {
	var body, status, keys string
	switch a.tab() {
	case tabWelcome:
		body, keys = a.viewWelcome()
	case tabDevices:
		body, keys = a.viewDevices()
	case tabAdmin:
		body, keys = a.viewAdmin()
	case tabSimple:
		body, status, keys = a.classic.Parts()
		if a.classic.screen == screenList && len(a.tabs) > 1 {
			keys += hint.Render("  ·  ") + keyHelp("tab", "switch")
		}
	}
	if status == "" {
		status = statusLine(a.msg, a.msgIsErr)
	}
	if a.m.kind != modalNone {
		body, keys = a.viewModal()
	}
	pad := lipgloss.NewStyle().Padding(0, 2)
	out := []string{a.viewHeader(), a.viewTabs(), "", pad.Render(body)}
	used := lipgloss.Height(strings.Join(out, "\n")) + 3
	if gap := a.height - used; gap > 0 {
		out = append(out, strings.Repeat("\n", gap-1))
	} else {
		out = append(out, "")
	}
	out = append(out, pad.Render(status), pad.Render(keys))
	return clip(strings.Join(out, "\n"), a.width)
}

// clip cuts every line to the window width, so nothing wraps on a small
// terminal and pushes the header off screen.
func clip(s string, w int) string {
	if w <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			lines[i] = ansi.Truncate(l, w-1, "…")
		}
	}
	return strings.Join(lines, "\n")
}

func (a *App) viewHeader() string {
	left := titleBar.Render("wgh")
	info := ""
	switch a.tab() {
	case tabDevices:
		info = a.devInfo()
	case tabAdmin:
		if a.adm != nil {
			online := 0
			for _, d := range a.adm.Devices {
				if d.Online {
					online++
				}
			}
			info = fmt.Sprintf("coordinator  %s  %d devices, %d online", a.adm.Subnet, len(a.adm.Devices), online)
		} else {
			info = "coordinator"
		}
	case tabSimple:
		info = a.classic.Info()
	case tabWelcome:
		info = "your own WireGuard mesh"
	}
	right := ""
	if a.latest != "" {
		right = badge.Render(a.latest + " available · run wgh update")
	} else if a.o.Version != "" {
		right = infoBar.Render("v" + strings.TrimPrefix(a.o.Version, "v"))
	}
	mid := infoBar.Render(info)
	gap := a.width - lipgloss.Width(left) - lipgloss.Width(mid) - lipgloss.Width(right)
	if gap < 1 {
		mid = infoBar.Render(fit(info, max(a.width-lipgloss.Width(left)-lipgloss.Width(right)-3, 0)))
		gap = 1
	}
	return left + mid + strings.Repeat(" ", max(gap, 1)) + right
}

func (a *App) devInfo() string {
	if a.dev == nil {
		if a.agentState != nil {
			return a.agentState.Name + "  " + a.agentState.Address
		}
		return "this device"
	}
	s := a.dev
	conn := "connected"
	if !s.Connected {
		conn = "coordinator unreachable"
	}
	parts := []string{s.Name, s.Address, conn}
	if s.ExitNode != "" {
		if s.ExitActive {
			parts = append(parts, "exit via "+s.ExitNode)
		} else {
			parts = append(parts, "exit "+s.ExitNode+" waiting")
		}
	}
	if s.DryRun {
		parts = append(parts, "dry run")
	}
	return strings.Join(parts, "  ")
}

func (a *App) viewTabs() string {
	if len(a.tabs) < 2 {
		return ""
	}
	var parts []string
	for i, t := range a.tabs {
		label := fmt.Sprintf("%d %s", i+1, t)
		if i == a.cur {
			parts = append(parts, tabOn.Render(label))
		} else {
			parts = append(parts, tabOff.Render(label))
		}
	}
	return "  " + strings.Join(parts, " ")
}

func (a *App) bodyHeight() int {
	// header, tabs, blank, ..., blank, status, keys, detail panel
	return max(a.height-12, 3)
}

func (a *App) viewWelcome() (string, string) {
	var b strings.Builder
	b.WriteString(heading.Render("Welcome to wgh") + "\n")
	b.WriteString(hint.Render("A self-hosted WireGuard mesh: every device reaches every other one, directly\nwhere it can and through your own relay where it can't. No accounts, no cloud.") + "\n\n")
	for i, it := range welcomeItems {
		marker, t := "  ", value
		if i == a.welSel {
			marker, t = focusedPrompt.Render("▌ "), heading
		}
		b.WriteString(marker + t.Render(it.title) + "\n    " + hint.Render(it.sub) + "\n\n")
	}
	return strings.TrimRight(b.String(), "\n"), keyHelp("↑/↓", "move", "enter", "choose", "?", "help", "q", "quit")
}

func (a *App) viewDevices() (string, string) {
	keys := keyHelp("↑/↓", "move", "x", "use as exit", "X", "exit off", "R", "new key", "tab", "switch", "?", "help", "q", "quit")
	if a.dev == nil {
		msg := "Waiting for wgh up…"
		if a.devErr != nil {
			msg = "wgh up is not running on this device."
		}
		body := panel.Render(heading.Render(msg) + "\n\n" +
			value.Render("Start it in another terminal (it needs root):") + "\n\n  " +
			keyStyle.Render(upCommand(a.o.AgentState)) + "\n\n" +
			hint.Render("This screen fills in by itself once it's running."))
		return body, keyHelp("tab", "switch", "?", "help", "q", "quit")
	}
	s := a.dev
	cols := []col{
		{title: " ", width: 1},
		{title: "NAME", width: 14},
		{title: "ADDRESS", width: 12},
		{title: "PATH", width: 12},
		{title: "ENDPOINT", width: 0, min: 16},
		{title: "HANDSHAKE", width: 9, min: 9},
		{title: "↓ RX", width: 9, min: 9},
		{title: "↑ TX", width: 9, min: 9},
	}
	var rows [][]cell
	for _, p := range s.Peers {
		dot := cs("○", dotOff)
		if p.Online {
			dot = cs("●", dotOn)
		}
		if p.Relay {
			dot = cs("◆", keyStyle)
		}
		path := cs(p.Path, dim)
		switch p.Path {
		case agent.PathDirect:
			path = cs(p.Path, pathDir)
		case agent.PathRelay:
			path = cs(p.Path, pathRel)
		}
		name := p.Name
		if s.ExitNode == p.Name {
			name += " ⇄"
		}
		ep := p.Endpoint
		if ep == "" {
			ep = "-"
		}
		rows = append(rows, []cell{dot, c(name), c(p.Address), path, cs(ep, dim),
			c(app.Ago(s.At, p.LastHandshake)), c(app.Bytes(p.RxBytes)), c(app.Bytes(p.TxBytes))})
	}
	var b strings.Builder
	if len(rows) == 0 {
		b.WriteString(panel.Render(heading.Render("No other devices yet") + "\n\n" +
			value.Render("Make a token on the coordinator with ") + keyStyle.Render("wgh admin token") + "\n" +
			value.Render("and run ") + keyStyle.Render("wgh join <token>") + value.Render(" on the next device.")))
	} else {
		b.WriteString(grid(cols, rows, a.devSel, a.width-4, a.bodyHeight()))
		if p := a.devSelected(); p != nil {
			b.WriteString("\n\n" + a.devDetail(p))
		}
	}
	if note := devNotes(s); note != "" {
		b.WriteString("\n\n" + note)
	}
	return b.String(), keys
}

func upCommand(statePath string) string {
	if statePath == agent.DefaultPath() || statePath == "/var/lib/wgh/agent.json" {
		return "sudo wgh up"
	}
	return "sudo wgh up --state " + statePath
}

func (a *App) devDetail(p *agent.PeerStatus) string {
	var facts []string
	switch {
	case p.Relay:
		facts = append(facts, "relay server: carries traffic when no direct path works")
	case p.Static:
		facts = append(facts, "plain WireGuard device, reached through the relay")
	case p.Path == agent.PathDirect:
		facts = append(facts, "direct connection")
	case p.Path == agent.PathRelay:
		facts = append(facts, "relayed: no direct path yet, still trying")
	default:
		if !p.LastSeen.IsZero() {
			facts = append(facts, "offline, last seen "+app.Ago(a.dev.At, p.LastSeen))
		} else {
			facts = append(facts, "offline")
		}
	}
	if p.OS != "" {
		facts = append(facts, p.OS)
	}
	if len(p.Routes) > 0 {
		facts = append(facts, "shares "+strings.Join(p.Routes, ", "))
	}
	if p.Exit {
		if a.dev.ExitNode == p.Name {
			facts = append(facts, "your exit node")
		} else {
			facts = append(facts, "exit node available (x)")
		}
	}
	return heading.Render(p.Name) + hint.Render("  "+strings.Join(facts, " · "))
}

func devNotes(s *agent.Status) string {
	var lines []string
	if !s.Connected && s.LastError != "" {
		lines = append(lines, errStyle.Render("Coordinator: ")+value.Render(s.LastError))
	}
	if s.ExitNode != "" && !s.ExitActive && s.ExitNote != "" {
		lines = append(lines, errStyle.Render("Exit node: ")+value.Render(s.ExitNote))
	}
	if len(s.PendingRoutes) > 0 || s.PendingExit {
		lines = append(lines, hint.Render("This device's shared routes or exit node wait for approval on the coordinator."))
	}
	return strings.Join(lines, "\n")
}

func (a *App) viewAdmin() (string, string) {
	keys := keyHelp("t", "token", "p", "add phone", "a", "approve", "d", "remove", "enter", "phone QR", "tab", "switch", "q", "quit")
	if a.adm == nil {
		msg := "Connecting to the coordinator…"
		if a.admErr != nil {
			msg = "Can't reach wgh serve: " + a.admErr.Error()
		}
		return panel.Render(value.Render(msg)), keyHelp("tab", "switch", "q", "quit")
	}
	if len(a.adm.Devices) == 0 {
		return panel.Render(heading.Render("No devices yet") + "\n\n" +
			value.Render("Press ") + keyStyle.Render("t") + value.Render(" for a join token, or ") +
			keyStyle.Render("p") + value.Render(" to add a phone.")), keys
	}
	cols := []col{
		{title: " ", width: 1},
		{title: "NAME", width: 14},
		{title: "ADDRESS", width: 12},
		{title: "LAST SEEN", width: 10},
		{title: "OS", width: 9, min: 9},
		{title: "SHARES", width: 0, min: 12},
		{title: "NOTE", width: 16, min: 16},
	}
	now := a.o.Now()
	var rows [][]cell
	for _, d := range a.adm.Devices {
		dot := cs("○", dotOff)
		if d.Online {
			dot = cs("●", dotOn)
		}
		shares := append(append([]string(nil), d.Routes...), d.PendingRoutes...)
		if d.Exit || d.PendingExit {
			shares = append(shares, "exit")
		}
		note := cs("", dim)
		switch {
		case len(d.PendingRoutes) > 0 || d.PendingExit:
			note = cs("needs approval", errStyle)
		case d.Static:
			note = cs("phone", dim)
		case d.Exit:
			note = cs("exit node", dim)
		}
		seen := app.Ago(now, d.LastSeen)
		if d.Online {
			seen = "now"
		}
		rows = append(rows, []cell{dot, c(d.Name), c(d.Address), c(seen), cs(orDash(d.OS), dim), c(orDash(strings.Join(shares, ", "))), note})
	}
	return grid(cols, rows, a.admSel, a.width-4, a.bodyHeight()+2), keys
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *App) viewModal() (string, string) {
	switch a.m.kind {
	case modalConfirm:
		return panel.Render(heading.Render(a.m.title) + "\n\n" + value.Render(a.m.body)), keyHelp("y", "yes", "n", "no")
	case modalInput:
		body := heading.Render(a.m.title) + "\n" + hint.Render(a.m.body) + "\n\n" + a.m.input.View()
		if a.m.two {
			body = heading.Render(a.m.title) + "\n" + hint.Render(a.m.body) + "\n\n" +
				label.Render("Token") + "\n" + a.m.input.View() + "\n\n" +
				label.Render("Name for this device") + "\n" + a.m.input2.View()
		}
		return body, keyHelp("enter", "ok", "tab", "next field", "esc", "cancel")
	case modalQR:
		qr := qrStyle.Render(a.m.body)
		title := heading.Render(a.m.title) + "\n" + hint.Render("It holds the device's private key: don't screenshot or share it.")
		if need := lipgloss.Height(qr) + 9; a.height < need || a.width < lipgloss.Width(qr)+4 {
			return title + "\n\n" + errStyle.Render(fmt.Sprintf("The window is too small for the QR code (needs %dx%d, have %dx%d).",
				lipgloss.Width(qr)+4, need, a.width, a.height)) + "\n" +
				value.Render("Make it bigger or zoom out, or run: wgh admin qr <name>"), keyHelp("esc", "back")
		}
		return title + "\n\n" + qr, keyHelp("esc", "back")
	}
	return heading.Render(a.m.title) + "\n\n" + a.m.body, keyHelp("esc", "back")
}

func helpFor(t tab) string {
	common := "\n\n" + keyStyle.Render("tab / 1-4") + hint.Render("   switch tabs") + "\n" +
		keyStyle.Render("q") + hint.Render("           quit")
	switch t {
	case tabDevices:
		return value.Render("Every device in your mesh, live:") + "\n\n" +
			keyStyle.Render("↑/↓") + hint.Render("   pick a device") + "\n" +
			keyStyle.Render("x") + hint.Render("     send your internet traffic through it (exit node)") + "\n" +
			keyStyle.Render("X") + hint.Render("     stop using an exit node") + "\n" +
			keyStyle.Render("R") + hint.Render("     switch this device to a new WireGuard key") + "\n" +
			keyStyle.Render("r") + hint.Render("     refresh now") + "\n\n" +
			value.Render("PATH is direct when the two devices reach each other, relay when traffic\ngoes through your coordinator because a firewall or NAT is in the way.") + common
	case tabAdmin:
		return value.Render("The coordinator's view of the mesh:") + "\n\n" +
			keyStyle.Render("t") + hint.Render("      make a join token") + "\n" +
			keyStyle.Render("p") + hint.Render("      add a phone (shows a QR code for the WireGuard app)") + "\n" +
			keyStyle.Render("enter") + hint.Render("  show a phone's QR code again") + "\n" +
			keyStyle.Render("a") + hint.Render("      approve shared routes and exit nodes") + "\n" +
			keyStyle.Render("d") + hint.Render("      remove a device") + common
	case tabSimple:
		return helpText
	}
	return value.Render(coordinatorHelp) + common
}

const coordinatorHelp = `The coordinator keeps the device list and runs the relay. Put it on a machine
every device can reach: a small VPS, or a box at home with UDP 51820 and
TCP 8443 forwarded.

  sudo wgh serve --endpoint vpn.example.com          add --exit to offer it as exit node
  sudo wgh admin token                               then on each device:
  sudo wgh join <token> && sudo wgh up

Phones use the normal WireGuard app: sudo wgh admin phone <name>.
The README has systemd units for both sides.`
