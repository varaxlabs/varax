package cli

import (
	"testing"
	"time"

	"github.com/varax/operator/pkg/models"
	"github.com/stretchr/testify/assert"
)

func makeTestResults() (*models.ComplianceResult, *models.ScanResult) {
	scanResult := &models.ScanResult{
		ID:        "test-scan-1",
		Timestamp: time.Now(),
		Duration:  3 * time.Second,
		Results: []models.CheckResult{
			{ID: "CIS-5.1.1", Name: "Cluster Admin", Severity: models.SeverityCritical, Status: models.StatusFail, Evidence: []models.Evidence{{Message: "found"}}},
			{ID: "CIS-5.2.3", Name: "Privileged", Severity: models.SeverityCritical, Status: models.StatusPass},
			{ID: "CIS-5.3.2", Name: "Network Policy", Severity: models.SeverityHigh, Status: models.StatusFail, Evidence: []models.Evidence{{Message: "missing"}}},
		},
		Summary: models.ScanSummary{
			TotalChecks: 3,
			PassCount:   1,
			FailCount:   2,
			WarnCount:   0,
			SkipCount:   0,
		},
	}

	complianceResult := &models.ComplianceResult{
		Framework: "SOC2",
		Score:     55.5,
		ControlResults: []models.ControlResult{
			{Control: models.Control{ID: "CC6.1", Name: "Access Control"}, Status: models.ControlStatusPass},
			{Control: models.Control{ID: "CC6.2", Name: "Auth Mechanisms"}, Status: models.ControlStatusFail, ViolationCount: 2},
			{Control: models.Control{ID: "CC7.1", Name: "Monitoring"}, Status: models.ControlStatusPartial, ViolationCount: 1},
			{Control: models.Control{ID: "CC8.1", Name: "Change Mgmt"}, Status: models.ControlStatusNotAssessed},
		},
	}

	return complianceResult, scanResult
}

func TestSummaryBox_ContainsExpectedContent(t *testing.T) {
	cr, sr := makeTestResults()
	result := SummaryBox(cr, sr)

	assert.Contains(t, result, "Varax Compliance Summary")
	assert.Contains(t, result, "SOC2")
	assert.Contains(t, result, "56/100") // 55.5 rounds to 56
	assert.Contains(t, result, "3")
}

func TestSummaryBoxPlain_ContainsExpectedContent(t *testing.T) {
	cr, sr := makeTestResults()
	result := SummaryBoxPlain(cr, sr)

	assert.Contains(t, result, "Varax Compliance Summary")
	assert.Contains(t, result, "SOC2")
	assert.Contains(t, result, "56/100") // 55.5 rounds to 56
	assert.Contains(t, result, "3 total")
	assert.Contains(t, result, "1 pass")
	assert.Contains(t, result, "2 fail")
}

func TestSummaryBoxPlain_CriticalFindings(t *testing.T) {
	cr, sr := makeTestResults()
	result := SummaryBoxPlain(cr, sr)

	assert.Contains(t, result, "critical finding(s)")
}

func TestSummaryBoxPlain_NoCriticals(t *testing.T) {
	cr, sr := makeTestResults()
	// Change all criticals to pass
	for i := range sr.Results {
		if sr.Results[i].Severity == models.SeverityCritical {
			sr.Results[i].Status = models.StatusPass
		}
	}
	result := SummaryBoxPlain(cr, sr)

	assert.NotContains(t, result, "critical finding")
}

func TestCountControlStatuses(t *testing.T) {
	cr, _ := makeTestResults()
	pass, fail, partial, na := countControlStatuses(cr)

	assert.Equal(t, 1, pass)
	assert.Equal(t, 1, fail)
	assert.Equal(t, 1, partial)
	assert.Equal(t, 1, na)
}

func TestCountCriticalFindings(t *testing.T) {
	_, sr := makeTestResults()
	count := countCriticalFindings(sr)
	assert.Equal(t, 1, count) // Only CIS-5.1.1 is CRITICAL+FAIL
}
