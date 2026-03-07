package reports

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/varax/operator/pkg/cli"
	"github.com/varax/operator/pkg/models"
)

var (
	termTitleBox = lipgloss.NewStyle().
			Bold(true).
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(1, 3).
			MarginBottom(1)

	termSectionHeader = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#7D56F4")).
				MarginTop(1).
				MarginBottom(1)

	termDivider = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))
)

func (g *Generator) writeTerminal(outputPath string, data *ReportData) error {
	content := renderTerminalReport(data)
	return writeTerminalOutput(outputPath, content)
}

func renderTerminalReport(data *ReportData) string {
	var b strings.Builder

	// Title box
	titleContent := fmt.Sprintf("%s\nCluster: %s\nDate: %s\nVarax %s",
		data.ReportTitle,
		data.ClusterName,
		data.GeneratedAt.Format("2006-01-02 15:04 UTC"),
		data.VaraxVersion,
	)
	b.WriteString(termTitleBox.Render(titleContent))
	b.WriteString("\n\n")

	// Score gauge
	if data.Compliance != nil {
		b.WriteString(termSectionHeader.Render("Compliance Score"))
		b.WriteString("\n")
		b.WriteString("  " + cli.ScoreGauge(data.Compliance.Score))
		b.WriteString("\n\n")
	}

	// Score trend
	if len(data.HistoricalScores) > 1 {
		b.WriteString(termSectionHeader.Render("Score Trend"))
		b.WriteString("\n")
		b.WriteString("  " + cli.ScoreTrend(data.HistoricalScores))
		b.WriteString("\n\n")
	}

	// Summary
	b.WriteString(termSectionHeader.Render("Summary"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  Total Checks:       %d\n", data.TotalChecks))
	b.WriteString(fmt.Sprintf("  Pass:               %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Render(fmt.Sprintf("%d", data.PassCount))))
	b.WriteString(fmt.Sprintf("  Fail:               %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4672")).Render(fmt.Sprintf("%d", data.FailCount))))
	b.WriteString(fmt.Sprintf("  Warn:               %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(fmt.Sprintf("%d", data.WarnCount))))
	b.WriteString(fmt.Sprintf("  Skip:               %d\n", data.SkipCount))
	if data.ProviderManagedCount > 0 {
		b.WriteString(fmt.Sprintf("  Provider-Managed:   %d\n", data.ProviderManagedCount))
	}
	b.WriteString(fmt.Sprintf("  Duration:           %s\n", data.ScanDuration))
	b.WriteString("\n")

	// Controls table
	if data.Compliance != nil && len(data.Compliance.ControlResults) > 0 {
		b.WriteString(termSectionHeader.Render("Controls"))
		b.WriteString("\n")
		b.WriteString(cli.ControlTable(data.Compliance.ControlResults))
		b.WriteString("\n")
	}

	// Top findings
	if len(data.TopFindings) > 0 {
		b.WriteString(termSectionHeader.Render("Top Findings"))
		b.WriteString("\n")
		for _, f := range data.TopFindings {
			sev := renderSeverityBadge(f.Severity)
			b.WriteString(fmt.Sprintf("  %s  %-12s %s\n", sev, f.ID, f.Name))
			if f.Message != "" {
				b.WriteString(fmt.Sprintf("                       %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#626262")).Render(f.Message)))
			}
			if rem := Remediation(f.ID); rem != "" {
				b.WriteString(fmt.Sprintf("                       %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render("Fix: "+rem)))
			}
			b.WriteString("\n")
		}
	}

	// Provider-managed section
	if len(data.ProviderManagedChecks) > 0 {
		b.WriteString(termSectionHeader.Render("Shared Responsibility (Provider-Managed)"))
		b.WriteString("\n")
		for _, c := range data.ProviderManagedChecks {
			b.WriteString(fmt.Sprintf("  %-12s %s\n", c.ID, c.Name))
		}
		b.WriteString("\n")
	}

	b.WriteString(termDivider.Render(strings.Repeat("─", 60)))
	b.WriteString("\n")

	return b.String()
}

func renderSeverityBadge(sev models.Severity) string {
	switch sev {
	case models.SeverityCritical:
		return cli.BadgeFail.Render("CRIT")
	case models.SeverityHigh:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4672")).Render("HIGH")
	case models.SeverityMedium:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(" MED")
	case models.SeverityLow:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#626262")).Render(" LOW")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#626262")).Render("INFO")
	}
}

func writeTerminalOutput(outputPath, content string) error {
	if outputPath == "" || outputPath == "-" {
		_, err := fmt.Fprint(os.Stdout, content)
		return err
	}
	return os.WriteFile(outputPath, []byte(content), 0600)
}
