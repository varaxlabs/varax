package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ScoreTrend renders a score trend line from historical scores.
// scores should be in chronological order (oldest first).
func ScoreTrend(scores []float64) string {
	if len(scores) == 0 {
		return "No history available"
	}

	current := scores[len(scores)-1]

	var change string
	if len(scores) >= 2 {
		prev := scores[len(scores)-2]
		diff := current - prev
		switch {
		case diff > 0:
			change = fmt.Sprintf(" (%s +%.0f from last scan)", upArrow, diff)
		case diff < 0:
			change = fmt.Sprintf(" (%s %.0f from last scan)", downArrow, diff)
		default:
			change = " (no change)"
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Score: %.0f%%%s\n", current, change)
	fmt.Fprintf(&b, "Trend: %s", sparkline(scores))
	return b.String()
}

// ScoreTrendPlain renders a plain-text score trend (no ANSI).
func ScoreTrendPlain(scores []float64) string {
	if len(scores) == 0 {
		return "No history available"
	}

	current := scores[len(scores)-1]

	var change string
	if len(scores) >= 2 {
		prev := scores[len(scores)-2]
		diff := current - prev
		switch {
		case diff > 0:
			change = fmt.Sprintf(" (^ +%.0f from last scan)", diff)
		case diff < 0:
			change = fmt.Sprintf(" (v %.0f from last scan)", diff)
		default:
			change = " (no change)"
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Score: %.0f%%%s\n", current, change)
	fmt.Fprintf(&b, "Trend: [%s]", plainSparkline(scores))
	return b.String()
}

const (
	upArrow   = "▲"
	downArrow = "▼"
)

var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// sparkline renders a sparkline chart from scores (0-100 range).
func sparkline(scores []float64) string {
	if len(scores) == 0 {
		return ""
	}

	var b strings.Builder
	for _, s := range scores {
		idx := int(s / 100.0 * float64(len(sparkChars)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		b.WriteRune(sparkChars[idx])
	}

	result := b.String()

	// Color the sparkline based on latest score
	latest := scores[len(scores)-1]
	var style lipgloss.Style
	switch {
	case latest >= 80:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("42")) // green
	case latest >= 50:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("214")) // yellow
	default:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("196")) // red
	}

	return style.Render(result)
}

// plainSparkline renders a plain ASCII sparkline from scores.
func plainSparkline(scores []float64) string {
	var b strings.Builder
	for i, s := range scores {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%.0f", s)
	}
	return b.String()
}
