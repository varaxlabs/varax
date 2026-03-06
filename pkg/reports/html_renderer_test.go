package reports

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

func testReportData() *ReportData {
	return &ReportData{
		ReportTitle:  "SOC2 Readiness Assessment",
		GeneratedAt:  time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC),
		VaraxVersion: "1.0.0-test",
		ClusterName:  "test-cluster",
		Compliance: &models.ComplianceResult{
			Framework: "SOC2",
			Score:     75.0,
			ControlResults: []models.ControlResult{
				{
					Control: models.Control{
						ID:          "CC6.1",
						Name:        "Logical Access",
						Description: "Access controls",
					},
					Status:         models.ControlStatusPass,
					ViolationCount: 0,
					CheckResults: []models.CheckResult{
						{
							ID:       "CIS-5.1.1",
							Name:     "RBAC check",
							Severity: models.SeverityHigh,
							Status:   models.StatusPass,
							Message:  "RBAC is enabled",
						},
					},
				},
				{
					Control: models.Control{
						ID:          "CC6.6",
						Name:        "Network Security",
						Description: "Network controls",
					},
					Status:         models.ControlStatusFail,
					ViolationCount: 2,
				},
			},
		},
		Scan: &models.ScanResult{
			Results: []models.CheckResult{
				{
					ID:       "CIS-5.1.1",
					Name:     "RBAC check",
					Severity: models.SeverityHigh,
					Status:   models.StatusPass,
					Message:  "RBAC is enabled",
				},
				{
					ID:       "CIS-5.3.2",
					Name:     "Network policies",
					Severity: models.SeverityCritical,
					Status:   models.StatusFail,
					Message:  "Missing network policies",
				},
			},
		},
		PassControls:    1,
		FailControls:    1,
		PartialControls: 0,
		NAControls:      0,
		CriticalCount:   1,
		HighCount:       0,
		TopFindings: []models.CheckResult{
			{
				ID:       "CIS-5.3.2",
				Name:     "Network policies",
				Severity: models.SeverityCritical,
				Status:   models.StatusFail,
				Message:  "Missing network policies",
			},
		},
		HistoricalScores: []float64{60.0, 70.0, 75.0},
	}
}

func TestRenderReadinessHTML_ToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "readiness.html")

	err := renderReadinessHTML(outPath, testReportData())
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)

	html := string(content)
	assert.Contains(t, html, "<!DOCTYPE html>")
	assert.Contains(t, html, "VARAX")
	assert.Contains(t, html, "SOC2 Readiness Assessment")
	assert.Contains(t, html, "test-cluster")
	assert.Contains(t, html, "CC6.1")
	assert.Contains(t, html, "75%")
	assert.Contains(t, html, "CIS-5.1.1")
}

func TestRenderExecutiveHTML_ToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "executive.html")

	data := testReportData()
	data.ReportTitle = "SOC2 Executive Summary"

	err := renderExecutiveHTML(outPath, data)
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)

	html := string(content)
	assert.Contains(t, html, "<!DOCTYPE html>")
	assert.Contains(t, html, "SOC2 Executive Summary")
	assert.Contains(t, html, "CC6.1")
	assert.Contains(t, html, "CC6.6")
}

func TestRenderControlDetailHTML_ToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "control.html")

	detail := &ControlDetail{
		Control: models.ControlResult{
			Control: models.Control{
				ID:          "CC6.1",
				Name:        "Logical Access",
				Description: "Access controls",
			},
			Status: models.ControlStatusPass,
			CheckResults: []models.CheckResult{
				{
					ID:       "CIS-5.1.1",
					Name:     "RBAC check",
					Severity: models.SeverityHigh,
					Status:   models.StatusPass,
					Message:  "RBAC is enabled",
				},
			},
		},
		Evidence: []evidence.EvidenceItem{
			{
				Category:    "RBAC",
				Description: "ClusterRole listing",
				Data:        map[string]string{"role": "admin"},
				Timestamp:   time.Now(),
			},
		},
	}

	err := renderControlDetailHTML(outPath, detail, "1.0.0")
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)

	html := string(content)
	assert.Contains(t, html, "<!DOCTYPE html>")
	assert.Contains(t, html, "CC6.1")
	assert.Contains(t, html, "RBAC")
	assert.Contains(t, html, "CIS-5.1.1")
}

func TestRenderReadinessHTML_MinimalData(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "minimal.html")

	data := &ReportData{
		ReportTitle:  "SOC2 Readiness Assessment",
		GeneratedAt:  time.Now(),
		VaraxVersion: "test",
		Compliance: &models.ComplianceResult{
			Framework: "SOC2",
			Score:     0,
		},
	}

	err := renderReadinessHTML(outPath, data)
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "<!DOCTYPE html>")
}

func TestRenderReadinessHTML_Stdout(t *testing.T) {
	data := testReportData()
	// Empty path means stdout - just verify no error
	// Redirect stdout to avoid noise
	old := os.Stdout
	f, err := os.CreateTemp("", "stdout")
	require.NoError(t, err)
	defer func() { _ = os.Remove(f.Name()) }()
	os.Stdout = f
	defer func() { os.Stdout = old }()

	err = renderReadinessHTML("", data)
	require.NoError(t, err)
}

func TestWriteToFileOrStdout_InvalidPath(t *testing.T) {
	err := writeToFileOrStdout("/nonexistent/dir/file.html", func(w io.Writer) error {
		return nil
	})
	assert.Error(t, err)
}
