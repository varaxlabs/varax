package explore

import "github.com/charmbracelet/lipgloss"

var (
	colorGreen  = lipgloss.Color("#04B575")
	colorRed    = lipgloss.Color("#FF4672")
	colorYellow = lipgloss.Color("#FFD700")
	colorBlue   = lipgloss.Color("#7D56F4")
	colorGray   = lipgloss.Color("#626262")
	colorWhite  = lipgloss.Color("#FFFFFF")
	colorBlack  = lipgloss.Color("#000000")

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBlue).
			MarginBottom(1)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(colorGray).
			MarginTop(1)

	selectedRowStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorWhite).
				Background(colorBlue)

	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBlue).
			Width(16)

	valueStyle = lipgloss.NewStyle()

	evidenceBlockStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorGray).
				Padding(0, 1).
				MarginTop(1)

	remediationBlockStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorYellow).
				Padding(0, 1).
				MarginTop(1)

	badgePass = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(colorGreen).
			Padding(0, 1)

	badgeFail = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(colorRed).
			Padding(0, 1)

	badgePartial = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBlack).
			Background(colorYellow).
			Padding(0, 1)

	badgeNA = lipgloss.NewStyle().
		Bold(true).
		Foreground(colorWhite).
		Background(colorGray).
		Padding(0, 1)
)

func statusBadge(status string) string {
	switch status {
	case "PASS":
		return badgePass.Render("PASS")
	case "FAIL":
		return badgeFail.Render("FAIL")
	case "PARTIAL":
		return badgePartial.Render("PARTIAL")
	default:
		return badgeNA.Render("N/A")
	}
}

func severityBadge(severity string) string {
	switch severity {
	case "CRITICAL":
		return badgeFail.Render("CRITICAL")
	case "HIGH":
		return lipgloss.NewStyle().Bold(true).Foreground(colorRed).Render("HIGH")
	case "MEDIUM":
		return lipgloss.NewStyle().Bold(true).Foreground(colorYellow).Render("MEDIUM")
	case "LOW":
		return lipgloss.NewStyle().Foreground(colorGray).Render("LOW")
	default:
		return lipgloss.NewStyle().Foreground(colorGray).Render(severity)
	}
}
