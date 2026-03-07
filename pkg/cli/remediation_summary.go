package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/varax/operator/pkg/remediation"
)

// RemediationBox renders a styled summary of a remediation report.
func RemediationBox(report *remediation.RemediationReport) string {
	var b strings.Builder

	title := TitleStyle.Render("Remediation Report")
	b.WriteString(title + "\n\n")

	mode := "LIVE"
	if report.DryRun {
		mode = "DRY RUN"
	}
	fmt.Fprintf(&b, "  Mode:      %s\n", lipgloss.NewStyle().Bold(true).Render(mode))
	fmt.Fprintf(&b, "  Duration:  %s\n", report.Duration.Round(1e6))
	fmt.Fprintf(&b, "  Actions:   %d total\n\n", report.Summary.TotalActions)

	s := report.Summary
	fmt.Fprintf(&b, "  %s applied  %s dry-run  %s skipped  %s failed\n",
		lipgloss.NewStyle().Foreground(ColorGreen).Render(fmt.Sprintf("%d", s.AppliedCount)),
		lipgloss.NewStyle().Foreground(ColorBlue).Render(fmt.Sprintf("%d", s.DryRunCount)),
		lipgloss.NewStyle().Foreground(ColorYellow).Render(fmt.Sprintf("%d", s.SkippedCount)),
		lipgloss.NewStyle().Foreground(ColorRed).Render(fmt.Sprintf("%d", s.FailedCount)),
	)

	if len(report.Results) > 0 {
		b.WriteString("\n")
		for _, r := range report.Results {
			badge := remediationStatusBadge(r.Status)
			fmt.Fprintf(&b, "  %s %s %s/%s (%s)\n",
				badge, r.Action.CheckID, r.Action.TargetKind, r.Action.TargetName, r.Action.Field)
		}
	}

	return boxStyle.Render(b.String())
}

// RemediationBoxPlain renders a plain text remediation summary.
func RemediationBoxPlain(report *remediation.RemediationReport) string {
	var b strings.Builder

	b.WriteString("=== Remediation Report ===\n\n")

	mode := "LIVE"
	if report.DryRun {
		mode = "DRY RUN"
	}
	fmt.Fprintf(&b, "  Mode:      %s\n", mode)
	fmt.Fprintf(&b, "  Duration:  %s\n", report.Duration.Round(1e6))
	fmt.Fprintf(&b, "  Actions:   %d total\n\n", report.Summary.TotalActions)

	s := report.Summary
	fmt.Fprintf(&b, "  %d applied, %d dry-run, %d skipped, %d failed\n",
		s.AppliedCount, s.DryRunCount, s.SkippedCount, s.FailedCount)

	if len(report.Results) > 0 {
		b.WriteString("\n")
		for _, r := range report.Results {
			status := string(r.Status)
			detail := ""
			if r.SkipReason != "" {
				detail = fmt.Sprintf(" (%s)", r.SkipReason)
			}
			if r.Error != "" {
				detail = fmt.Sprintf(" (%s)", r.Error)
			}
			fmt.Fprintf(&b, "  [%s] %s %s/%s %s%s\n",
				status, r.Action.CheckID, r.Action.TargetKind, r.Action.TargetName, r.Action.Field, detail)
		}
	}

	return b.String()
}

func remediationStatusBadge(status remediation.ActionStatus) string {
	switch status {
	case remediation.StatusApplied:
		return BadgePass.Render("APPLIED")
	case remediation.StatusDryRun:
		return lipgloss.NewStyle().Bold(true).Foreground(ColorWhite).Background(ColorBlue).Padding(0, 1).Render("DRY RUN")
	case remediation.StatusSkipped:
		return BadgePartial.Render("SKIPPED")
	case remediation.StatusFailed:
		return BadgeFail.Render("FAILED")
	default:
		return BadgeNA.Render(string(status))
	}
}
