package reports

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
)

func TestRenderTerminalReport(t *testing.T) {
	data := &ReportData{
		ReportTitle:  "SOC2 Readiness Assessment",
		GeneratedAt:  time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC),
		VaraxVersion: "1.0.0",
		ClusterName:  "test-cluster",
		Compliance: &models.ComplianceResult{
			Framework: "SOC2",
			Score:     82.5,
			ControlResults: []models.ControlResult{
				{
					Control:        models.Control{ID: "CC6.1", Name: "Logical Access Controls"},
					Status:         models.ControlStatusFail,
					ViolationCount: 2,
				},
				{
					Control: models.Control{ID: "CC5.1", Name: "Control Activities"},
					Status:  models.ControlStatusPass,
				},
			},
		},
		Scan: &models.ScanResult{
			Summary: models.ScanSummary{
				TotalChecks: 20,
				PassCount:   15,
				FailCount:   3,
				WarnCount:   1,
				SkipCount:   1,
			},
		},
		TotalChecks: 20,
		PassCount:   15,
		FailCount:   3,
		WarnCount:   1,
		SkipCount:   1,
		TopFindings: []models.CheckResult{
			{
				ID:       "CIS-5.1.1",
				Name:     "Cluster-admin binding",
				Severity: models.SeverityHigh,
				Status:   models.StatusFail,
				Message:  "Found 3 cluster-admin bindings",
			},
		},
		HistoricalScores: []float64{70, 75, 80, 82.5},
	}

	output := renderTerminalReport(data)

	assert.Contains(t, output, "SOC2 Readiness Assessment")
	assert.Contains(t, output, "test-cluster")
	assert.Contains(t, output, "2026-03-07")
	assert.Contains(t, output, "Compliance Score")
	assert.Contains(t, output, "Score Trend")
	assert.Contains(t, output, "Summary")
	assert.Contains(t, output, "Controls")
	assert.Contains(t, output, "CC6.1")
	assert.Contains(t, output, "Top Findings")
	assert.Contains(t, output, "CIS-5.1.1")
}

func TestRenderTerminalReportNilOptionalFields(t *testing.T) {
	data := &ReportData{
		ReportTitle:  "SOC2 Report",
		GeneratedAt:  time.Now(),
		VaraxVersion: "1.0.0",
		ClusterName:  "test",
		Compliance: &models.ComplianceResult{
			Score: 50,
		},
		TotalChecks: 10,
		PassCount:   5,
		FailCount:   5,
	}

	output := renderTerminalReport(data)
	assert.Contains(t, output, "SOC2 Report")
	assert.NotContains(t, output, "Score Trend")
	assert.NotContains(t, output, "Top Findings")
	assert.NotContains(t, output, "Provider-Managed")
}

func TestTerminalReportStdout(t *testing.T) {
	err := writeTerminalOutput("", "test output")
	assert.NoError(t, err)

	err = writeTerminalOutput("-", "test output")
	assert.NoError(t, err)
}

func TestTerminalReportFileOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")

	content := "test report content"
	err := writeTerminalOutput(path, content)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, string(data))
}

func TestRenderSeverityBadge(t *testing.T) {
	assert.Contains(t, renderSeverityBadge("CRITICAL"), "CRIT")
	assert.Contains(t, renderSeverityBadge("HIGH"), "HIGH")
	assert.Contains(t, renderSeverityBadge("MEDIUM"), "MED")
	assert.Contains(t, renderSeverityBadge("LOW"), "LOW")
	assert.Contains(t, renderSeverityBadge("INFO"), "INFO")
}

func TestWriteTerminalViaGenerator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")

	gen := NewGenerator("1.0.0")
	data := &ReportData{
		GeneratedAt: time.Now(),
		ClusterName: "test",
		Compliance:  &models.ComplianceResult{Score: 80},
		TotalChecks: 5,
		PassCount:   4,
		FailCount:   1,
	}
	req := ReportRequest{
		Type:       ReportTypeReadiness,
		Format:     FormatTerminal,
		OutputPath: path,
	}

	err := gen.Generate(req, data)
	require.NoError(t, err)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "SOC2 Readiness Assessment")
}

func TestTerminalReportProviderManaged(t *testing.T) {
	data := &ReportData{
		ReportTitle:  "SOC2 Report",
		GeneratedAt:  time.Now(),
		VaraxVersion: "1.0.0",
		ClusterName:  "test",
		Compliance:   &models.ComplianceResult{Score: 80},
		ProviderManagedChecks: []models.CheckResult{
			{ID: "CIS-1.2.1", Name: "API Server RBAC"},
		},
		ProviderManagedCount: 1,
	}

	output := renderTerminalReport(data)
	assert.Contains(t, output, "Shared Responsibility")
	assert.Contains(t, output, "CIS-1.2.1")
}
