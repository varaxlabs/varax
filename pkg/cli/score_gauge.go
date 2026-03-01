package cli

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

const gaugeWidth = 20

// ScoreGauge renders a colored progress bar representing a compliance score.
func ScoreGauge(score float64) string {
	filled := int(score / 100 * float64(gaugeWidth))
	if filled > gaugeWidth {
		filled = gaugeWidth
	}
	empty := gaugeWidth - filled

	var color lipgloss.Color
	switch {
	case score >= 80:
		color = ColorGreen
	case score >= 50:
		color = ColorYellow
	default:
		color = ColorRed
	}

	filledStyle := lipgloss.NewStyle().Foreground(color)
	emptyStyle := lipgloss.NewStyle().Foreground(ColorGray)

	bar := ""
	for i := 0; i < filled; i++ {
		bar += filledStyle.Render("█")
	}
	for i := 0; i < empty; i++ {
		bar += emptyStyle.Render("░")
	}

	scoreStyle := lipgloss.NewStyle().Bold(true).Foreground(color)
	return fmt.Sprintf("%s %s", bar, scoreStyle.Render(fmt.Sprintf("%.0f/100", score)))
}

// ScoreGaugePlain renders a plain text score gauge.
func ScoreGaugePlain(score float64) string {
	filled := int(score / 100 * float64(gaugeWidth))
	if filled > gaugeWidth {
		filled = gaugeWidth
	}
	empty := gaugeWidth - filled

	bar := ""
	for i := 0; i < filled; i++ {
		bar += "#"
	}
	for i := 0; i < empty; i++ {
		bar += "-"
	}

	return fmt.Sprintf("[%s] %.0f/100", bar, score)
}
