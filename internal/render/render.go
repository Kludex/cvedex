// Package render turns CVE Services data into styled terminal text, shared by the CLI and the TUI.
package render

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"

	"github.com/Kludex/cvedex/cveservices"
)

// Styles shared by every view.
var (
	Bold   = lipgloss.NewStyle().Bold(true)
	Faint  = lipgloss.NewStyle().Faint(true)
	Label  = lipgloss.NewStyle().Faint(true).Width(11)
	Accent = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	Good   = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	Bad    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	Warn   = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
)

// StateColor is the color of a CVE ID or review state.
func StateColor(state string) color.Color {
	switch strings.ToUpper(state) {
	case cveservices.StatePublished, "APPROVED":
		return lipgloss.Color("10")
	case cveservices.StateRejected, "DENIED":
		return lipgloss.Color("9")
	case cveservices.StateReserved, "IN_REVIEW", "PENDING":
		return lipgloss.Color("11")
	}
	return lipgloss.NoColor{}
}

// State renders a state in its color.
func State(state string) string {
	return lipgloss.NewStyle().Foreground(StateColor(state)).Render(state)
}

// Table renders rows under a header, in plain aligned columns with no borders, so the output
// reads well in a terminal and still splits on whitespace in a pipe. style, when set, styles one
// cell of the body.
func Table(headers []string, rows [][]string, style func(row, col int) lipgloss.Style) string {
	cell := lipgloss.NewStyle().PaddingRight(3)
	return trimLines(table.New().
		Headers(headers...).
		Rows(rows...).
		Border(lipgloss.HiddenBorder()).
		BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
		BorderHeader(false).BorderColumn(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return cell.Faint(true)
			}
			if style != nil {
				return style(row, col).PaddingRight(3)
			}
			return cell
		}).
		String())
}

// trimLines drops the padding lipgloss leaves at the end of each line.
func trimLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " ")
	}
	return strings.Join(lines, "\n")
}

// IDs renders CVE IDs as a table.
func IDs(ids []cveservices.CVEID) string {
	rows := make([][]string, len(ids))
	for i, id := range ids {
		rows[i] = []string{id.ID, id.State, id.Reserved.Format("2006-01-02"), id.RequestedBy.User}
		if id.Cvedexd != nil {
			rows[i][1] += " (" + id.Cvedexd.State + ")"
		}
	}
	return Table([]string{"CVE ID", "STATE", "RESERVED", "BY"}, rows, func(row, col int) lipgloss.Style {
		if col == 1 {
			return lipgloss.NewStyle().Foreground(StateColor(ids[row].State))
		}
		return lipgloss.NewStyle()
	})
}
