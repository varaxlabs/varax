package reports

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/varax/operator/pkg/models"
)

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"statusClass":   statusClass,
		"severityClass": severityClass,
		"formatTime":    formatTime,
		"formatDate":    formatDate,
		"formatScore":   formatScore,
		"scoreClass":    scoreClass,
		"jsonPretty":    jsonPretty,
		"add":           func(a, b int) int { return a + b },
		"sub":           func(a, b int) int { return a - b },
		"seq":           seq,
		"upper":         strings.ToUpper,
		"css":           func() template.CSS { return template.CSS(reportCSS) },
		"controlStatusClass": controlStatusClass,
		"truncate":      truncate,
	}
}

func statusClass(s models.CheckStatus) string {
	switch s {
	case models.StatusPass:
		return "status-pass"
	case models.StatusFail:
		return "status-fail"
	case models.StatusWarn:
		return "status-warn"
	case models.StatusSkip:
		return "status-skip"
	default:
		return "status-unknown"
	}
}

func controlStatusClass(s models.ControlStatus) string {
	switch s {
	case models.ControlStatusPass:
		return "status-pass"
	case models.ControlStatusFail:
		return "status-fail"
	case models.ControlStatusPartial:
		return "status-partial"
	case models.ControlStatusNotAssessed:
		return "status-na"
	default:
		return "status-unknown"
	}
}

func severityClass(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "severity-critical"
	case models.SeverityHigh:
		return "severity-high"
	case models.SeverityMedium:
		return "severity-medium"
	case models.SeverityLow:
		return "severity-low"
	case models.SeverityInfo:
		return "severity-info"
	default:
		return "severity-unknown"
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.Format("2006-01-02 15:04:05 UTC")
}

func formatDate(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.Format("January 2, 2006")
}

func formatScore(score float64) string {
	return fmt.Sprintf("%.0f%%", score)
}

func scoreClass(score float64) string {
	switch {
	case score >= 80:
		return "score-high"
	case score >= 50:
		return "score-medium"
	default:
		return "score-low"
	}
}

func jsonPretty(v any) string {
	if v == nil {
		return "{}"
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(data)
}

func seq(n int) []int {
	if n <= 0 {
		return nil
	}
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
