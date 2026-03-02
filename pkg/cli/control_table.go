package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/varax/operator/pkg/models"
)

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorBlue).
			PaddingRight(2)

	cellStyle = lipgloss.NewStyle().PaddingRight(2)
)

// ControlTable renders a styled table of control results.
func ControlTable(results []models.ControlResult) string {
	var b strings.Builder

	// Header
	b.WriteString(fmt.Sprintf("  %s%s%s%s\n",
		headerStyle.Width(10).Render("ID"),
		headerStyle.Width(50).Render("Control"),
		headerStyle.Width(12).Render("Status"),
		headerStyle.Width(12).Render("Violations"),
	))

	b.WriteString(fmt.Sprintf("  %s\n", strings.Repeat("─", 84)))

	for _, cr := range results {
		badge := StatusBadge(string(cr.Status))

		b.WriteString(fmt.Sprintf("  %s%s%s%s\n",
			cellStyle.Width(10).Render(cr.Control.ID),
			cellStyle.Width(50).Render(truncate(cr.Control.Name, 48)),
			cellStyle.Width(12).Render(badge),
			cellStyle.Width(12).Render(fmt.Sprintf("%d", cr.ViolationCount)),
		))
	}

	return b.String()
}

// ControlTablePlain renders a plain text table of control results.
func ControlTablePlain(results []models.ControlResult) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  %-10s %-50s %-12s %s\n", "ID", "Control", "Status", "Violations"))
	b.WriteString(fmt.Sprintf("  %s\n", strings.Repeat("-", 84)))

	for _, cr := range results {
		b.WriteString(fmt.Sprintf("  %-10s %-50s %-12s %d\n",
			cr.Control.ID,
			truncate(cr.Control.Name, 48),
			string(cr.Status),
			cr.ViolationCount,
		))
	}

	return b.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
