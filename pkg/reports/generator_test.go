package reports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
)

func TestPopulateComputedFields(t *testing.T) {
	g := NewGenerator("test")
	data := &ReportData{
		Compliance: &models.ComplianceResult{
			Framework: "SOC2",
			Score:     75.0,
			ControlResults: []models.ControlResult{
				{Status: models.ControlStatusPass},
				{Status: models.ControlStatusPass},
				{Status: models.ControlStatusFail},
				{Status: models.ControlStatusPartial},
				{Status: models.ControlStatusNotAssessed},
			},
		},
		Scan: &models.ScanResult{
			Results: []models.CheckResult{
				{ID: "C1", Status: models.StatusFail, Severity: models.SeverityCritical},
				{ID: "C2", Status: models.StatusFail, Severity: models.SeverityHigh},
				{ID: "C3", Status: models.StatusFail, Severity: models.SeverityMedium},
				{ID: "C4", Status: models.StatusPass, Severity: models.SeverityHigh},
			},
		},
	}

	g.populateComputedFields(data)

	assert.Equal(t, 2, data.PassControls)
	assert.Equal(t, 1, data.FailControls)
	assert.Equal(t, 1, data.PartialControls)
	assert.Equal(t, 1, data.NAControls)
	assert.Equal(t, 1, data.CriticalCount)
	assert.Equal(t, 1, data.HighCount)
	assert.Len(t, data.TopFindings, 3)
	// Sorted by severity: critical first
	assert.Equal(t, models.SeverityCritical, data.TopFindings[0].Severity)
	assert.Equal(t, models.SeverityHigh, data.TopFindings[1].Severity)
}

func TestPopulateComputedFields_NilCompliance(t *testing.T) {
	g := NewGenerator("test")
	data := &ReportData{}
	g.populateComputedFields(data)
	// Should not panic
	assert.Equal(t, 0, data.PassControls)
}

func TestPopulateComputedFields_NilScan(t *testing.T) {
	g := NewGenerator("test")
	data := &ReportData{
		Compliance: &models.ComplianceResult{
			ControlResults: []models.ControlResult{
				{Status: models.ControlStatusPass},
			},
		},
	}
	g.populateComputedFields(data)
	assert.Equal(t, 1, data.PassControls)
	assert.Nil(t, data.TopFindings)
}

func TestSeverityRank(t *testing.T) {
	assert.Greater(t, severityRank(models.SeverityCritical), severityRank(models.SeverityHigh))
	assert.Greater(t, severityRank(models.SeverityHigh), severityRank(models.SeverityMedium))
	assert.Greater(t, severityRank(models.SeverityMedium), severityRank(models.SeverityLow))
	assert.Greater(t, severityRank(models.SeverityLow), severityRank("UNKNOWN"))
}

func TestGenerate_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.json")

	g := NewGenerator("1.0.0")
	data := &ReportData{
		GeneratedAt: time.Now(),
		ClusterName: "test",
		Compliance: &models.ComplianceResult{
			Framework: "SOC2",
			Score:     80.0,
		},
	}

	err := g.Generate(ReportRequest{
		Type:       ReportTypeReadiness,
		Format:     FormatJSON,
		OutputPath: outPath,
	}, data)
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal(content, &result))
	assert.Equal(t, "1.0.0", result["VaraxVersion"])
}

func TestGenerate_HTML(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.html")

	g := NewGenerator("1.0.0")
	data := &ReportData{
		GeneratedAt: time.Now(),
		ClusterName: "test",
		Compliance: &models.ComplianceResult{
			Framework: "SOC2",
			Score:     80.0,
		},
	}

	err := g.Generate(ReportRequest{
		Type:       ReportTypeReadiness,
		Format:     FormatHTML,
		OutputPath: outPath,
	}, data)
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "<!DOCTYPE html>")
	assert.Contains(t, string(content), "SOC2 Readiness Assessment")
}

func TestGenerate_ExecutiveHTML(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "executive.html")

	g := NewGenerator("1.0.0")
	data := &ReportData{
		GeneratedAt: time.Now(),
		ClusterName: "test",
		Compliance: &models.ComplianceResult{
			Framework: "SOC2",
			Score:     65.0,
			ControlResults: []models.ControlResult{
				{
					Control: models.Control{ID: "CC6.1", Name: "Access"},
					Status:  models.ControlStatusPass,
				},
			},
		},
	}

	err := g.Generate(ReportRequest{
		Type:       ReportTypeExecutive,
		Format:     FormatHTML,
		OutputPath: outPath,
	}, data)
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "SOC2 Executive Summary")
}

func TestGenerate_UnsupportedFormat(t *testing.T) {
	g := NewGenerator("1.0.0")
	err := g.Generate(ReportRequest{Format: "pdf"}, &ReportData{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

func TestGenerate_UnsupportedReportType(t *testing.T) {
	g := NewGenerator("1.0.0")
	err := g.Generate(ReportRequest{
		Format: FormatHTML,
		Type:   "detailed",
	}, &ReportData{
		Compliance: &models.ComplianceResult{Framework: "SOC2"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported report type")
}

func TestGenerateControlDetail_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "detail.json")

	g := NewGenerator("1.0.0")
	err := g.GenerateControlDetail(outPath, FormatJSON, models.ControlResult{
		Control: models.Control{ID: "CC6.1"},
		Status:  models.ControlStatusPass,
	}, nil, "1.0.0")
	require.NoError(t, err)

	content, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "CC6.1")
}

func TestGenerateControlDetail_UnsupportedFormat(t *testing.T) {
	g := NewGenerator("1.0.0")
	err := g.GenerateControlDetail("", "pdf", models.ControlResult{}, nil, "1.0.0")
	assert.Error(t, err)
}

func TestTopFindingsCappedAt10(t *testing.T) {
	g := NewGenerator("test")
	var results []models.CheckResult
	for i := 0; i < 15; i++ {
		results = append(results, models.CheckResult{
			Status:   models.StatusFail,
			Severity: models.SeverityMedium,
		})
	}
	data := &ReportData{
		Compliance: &models.ComplianceResult{},
		Scan:       &models.ScanResult{Results: results},
	}
	g.populateComputedFields(data)
	assert.Len(t, data.TopFindings, 10)
}
