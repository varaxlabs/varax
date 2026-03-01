package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/kubeshield/operator/pkg/models"
)

var boxStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(ColorBlue).
	Padding(1, 2)

// SummaryBox renders a bordered summary box with scan results.
func SummaryBox(result *models.ComplianceResult, scanResult *models.ScanResult) string {
	var b strings.Builder

	title := TitleStyle.Render("KubeShield Compliance Summary")
	b.WriteString(title + "\n\n")

	b.WriteString(fmt.Sprintf("  Framework:  %s\n", result.Framework))
	b.WriteString(fmt.Sprintf("  Score:      %s\n", ScoreGauge(result.Score)))
	b.WriteString(fmt.Sprintf("  Duration:   %s\n\n", scanResult.Duration.Round(1e6)))

	// Control counts
	pass, fail, partial, na := countControlStatuses(result)
	b.WriteString(fmt.Sprintf("  Controls:   %s pass  %s fail  %s partial  %s n/a\n",
		lipgloss.NewStyle().Foreground(ColorGreen).Render(fmt.Sprintf("%d", pass)),
		lipgloss.NewStyle().Foreground(ColorRed).Render(fmt.Sprintf("%d", fail)),
		lipgloss.NewStyle().Foreground(ColorYellow).Render(fmt.Sprintf("%d", partial)),
		lipgloss.NewStyle().Foreground(ColorGray).Render(fmt.Sprintf("%d", na)),
	))

	// Check summary
	b.WriteString(fmt.Sprintf("  Checks:     %d total, %d pass, %d fail\n",
		scanResult.Summary.TotalChecks,
		scanResult.Summary.PassCount,
		scanResult.Summary.FailCount,
	))

	// Critical findings
	criticals := countCriticalFindings(scanResult)
	if criticals > 0 {
		b.WriteString(fmt.Sprintf("\n  %s %d critical finding(s) require attention\n",
			ErrorStyle.Render("!"),
			criticals,
		))
	}

	return boxStyle.Render(b.String())
}

// SummaryBoxPlain renders a plain text summary.
func SummaryBoxPlain(result *models.ComplianceResult, scanResult *models.ScanResult) string {
	var b strings.Builder

	b.WriteString("=== KubeShield Compliance Summary ===\n\n")
	b.WriteString(fmt.Sprintf("  Framework:  %s\n", result.Framework))
	b.WriteString(fmt.Sprintf("  Score:      %s\n", ScoreGaugePlain(result.Score)))
	b.WriteString(fmt.Sprintf("  Duration:   %s\n\n", scanResult.Duration.Round(1e6)))

	pass, fail, partial, na := countControlStatuses(result)
	b.WriteString(fmt.Sprintf("  Controls:   %d pass, %d fail, %d partial, %d n/a\n", pass, fail, partial, na))
	b.WriteString(fmt.Sprintf("  Checks:     %d total, %d pass, %d fail\n",
		scanResult.Summary.TotalChecks,
		scanResult.Summary.PassCount,
		scanResult.Summary.FailCount,
	))

	criticals := countCriticalFindings(scanResult)
	if criticals > 0 {
		b.WriteString(fmt.Sprintf("\n  ! %d critical finding(s) require attention\n", criticals))
	}

	return b.String()
}

func countControlStatuses(result *models.ComplianceResult) (pass, fail, partial, na int) {
	for _, cr := range result.ControlResults {
		switch cr.Status {
		case models.ControlStatusPass:
			pass++
		case models.ControlStatusFail:
			fail++
		case models.ControlStatusPartial:
			partial++
		case models.ControlStatusNotAssessed:
			na++
		}
	}
	return
}

func countCriticalFindings(scanResult *models.ScanResult) int {
	count := 0
	for _, r := range scanResult.Results {
		if r.Severity == models.SeverityCritical && r.Status == models.StatusFail {
			count++
		}
	}
	return count
}
