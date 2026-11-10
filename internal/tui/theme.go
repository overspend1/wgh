package tui

import "github.com/charmbracelet/lipgloss"

// WireGuard's brand red, from its logo, plus a brighter red that stays
// readable as text on dark terminals.
var (
	red       = lipgloss.Color("#88171A")
	brightRed = lipgloss.AdaptiveColor{Light: "#A11D21", Dark: "#E5484D"}
	paleRed   = lipgloss.AdaptiveColor{Light: "#5C0F11", Dark: "#F4A3A6"}
	white     = lipgloss.Color("#FFFFFF")
	muted     = lipgloss.AdaptiveColor{Light: "#6B6B6B", Dark: "#8A8A8A"}
	text      = lipgloss.AdaptiveColor{Light: "#1A1A1A", Dark: "#EDEDED"}
	okGreen   = lipgloss.AdaptiveColor{Light: "#1E7B34", Dark: "#5BD17A"}
)

var (
	titleBar = lipgloss.NewStyle().Bold(true).Foreground(white).Background(red).Padding(0, 1)
	infoBar  = lipgloss.NewStyle().Foreground(paleRed).Padding(0, 1)
	badge    = lipgloss.NewStyle().Bold(true).Foreground(white).Background(brightRed).Padding(0, 1)

	heading  = lipgloss.NewStyle().Bold(true).Foreground(brightRed)
	label    = lipgloss.NewStyle().Foreground(muted)
	value    = lipgloss.NewStyle().Foreground(text)
	hint     = lipgloss.NewStyle().Foreground(muted)
	keyStyle = lipgloss.NewStyle().Bold(true).Foreground(brightRed)
	errStyle = lipgloss.NewStyle().Bold(true).Foreground(brightRed)
	okStyle  = lipgloss.NewStyle().Foreground(okGreen)

	panel = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(red).Padding(0, 1)

	focusedPrompt = lipgloss.NewStyle().Foreground(brightRed).Bold(true)
	blurredPrompt = lipgloss.NewStyle().Foreground(muted)

	// QR codes are drawn white-on-black whatever the terminal theme, so
	// phones can always scan them.
	qrStyle = lipgloss.NewStyle().Foreground(white).Background(lipgloss.Color("#000000"))
)
