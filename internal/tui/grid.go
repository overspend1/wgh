package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

// col is one column of a grid: a title and a width (0 = take what's left).
type col struct {
	title string
	width int
	min   int // drop the column when the window is too narrow for it
}

// cell is one value with an optional style.
type cell struct {
	text  string
	style lipgloss.Style
	plain bool // no style
}

func c(s string) cell                     { return cell{text: s, plain: true} }
func cs(s string, st lipgloss.Style) cell { return cell{text: s, style: st} }
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if runewidth.StringWidth(s) > w {
		return runewidth.Truncate(s, w, "…")
	}
	return s + strings.Repeat(" ", w-runewidth.StringWidth(s))
}

var (
	gridHead = lipgloss.NewStyle().Bold(true).Foreground(muted)
	gridSel  = lipgloss.NewStyle().Bold(true).Foreground(white).Background(red)
)

// grid renders rows under a header, keeping the selected row in view
// within height lines. Columns whose min is wider than the window drop out.
func grid(cols []col, rows [][]cell, selected, width, height int) string {
	keep := make([]int, 0, len(cols))
	total := 0
	for i, cl := range cols {
		w := max(cl.width, cl.min)
		if i > 0 && total+w+2 > width && cl.min > 0 {
			continue
		}
		keep = append(keep, i)
		total += w + 2
	}
	widths := make([]int, len(cols))
	flex := -1
	used := 0
	for _, i := range keep {
		if cols[i].width == 0 {
			flex = i
			continue
		}
		widths[i] = cols[i].width
		used += cols[i].width + 2
	}
	if flex >= 0 {
		widths[flex] = max(width-used-2, max(cols[flex].min, 4))
	}
	var b strings.Builder
	var head []string
	for _, i := range keep {
		head = append(head, gridHead.Render(fit(cols[i].title, widths[i])))
	}
	b.WriteString(strings.Join(head, "  ") + "\n")
	if height < 2 {
		height = 2
	}
	visible := height - 1
	start := 0
	if selected >= visible {
		start = selected - visible + 1
	}
	for r := start; r < len(rows) && r < start+visible; r++ {
		var parts []string
		for _, i := range keep {
			v := c("")
			if i < len(rows[r]) {
				v = rows[r][i]
			}
			txt := fit(v.text, widths[i])
			switch {
			case r == selected:
				parts = append(parts, gridSel.Render(txt))
			case v.plain:
				parts = append(parts, value.Render(txt))
			default:
				parts = append(parts, v.style.Render(txt))
			}
		}
		sep := "  "
		if r == selected {
			sep = gridSel.Render("  ")
		}
		b.WriteString(strings.Join(parts, sep) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
