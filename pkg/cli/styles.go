package cli

import "github.com/charmbracelet/lipgloss"

// Color palette
var (
	ColorGreen  = lipgloss.Color("#04B575")
	ColorRed    = lipgloss.Color("#FF4672")
	ColorYellow = lipgloss.Color("#FFD700")
	ColorBlue   = lipgloss.Color("#7D56F4")
	ColorGray   = lipgloss.Color("#626262")
	ColorWhite  = lipgloss.Color("#FFFFFF")
	ColorBlack  = lipgloss.Color("#000000")
)

// Badge styles for compliance status
var (
	BadgePass = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWhite).
			Background(ColorGreen).
			Padding(0, 1)

	BadgeFail = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWhite).
			Background(ColorRed).
			Padding(0, 1)

	BadgePartial = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorBlack).
			Background(ColorYellow).
			Padding(0, 1)

	BadgeNA = lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorWhite).
		Background(ColorGray).
		Padding(0, 1)

	// Text styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorBlue)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	ErrorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorRed)
)

// StatusBadge returns the styled badge for a given status string.
func StatusBadge(status string) string {
	switch status {
	case "PASS":
		return BadgePass.Render("PASS")
	case "FAIL":
		return BadgeFail.Render("FAIL")
	case "PARTIAL":
		return BadgePartial.Render("PARTIAL")
	default:
		return BadgeNA.Render("N/A")
	}
}
