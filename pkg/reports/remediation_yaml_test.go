package reports

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
)

func TestBuildRemediationsForControl_FailingChecks(t *testing.T) {
	cr := models.ControlResult{
		CheckResults: []models.CheckResult{
			{ID: "CIS-5.1.1", Name: "Restrict cluster-admin", Status: models.StatusPass, Severity: models.SeverityCritical},
			{ID: "CIS-5.1.3", Name: "Minimize wildcard use", Status: models.StatusFail, Severity: models.SeverityHigh},
			{ID: "CIS-5.1.8", Name: "Limit escalate perms", Status: models.StatusFail, Severity: models.SeverityHigh},
		},
	}

	details := BuildRemediationsForControl(cr)
	assert.Len(t, details, 2)
	assert.Equal(t, "CIS-5.1.3", details[0].CheckID)
	assert.NotEmpty(t, details[0].Description)
	assert.Contains(t, details[0].DryRunCmd, "CIS-5.1.3")
	assert.Contains(t, details[0].DryRunCmd, "--dry-run")
}

func TestBuildRemediationsForControl_NoFailures(t *testing.T) {
	cr := models.ControlResult{
		CheckResults: []models.CheckResult{
			{ID: "CIS-5.1.1", Status: models.StatusPass},
		},
	}
	details := BuildRemediationsForControl(cr)
	assert.Empty(t, details)
}

func TestBuildRemediationsForControl_UnknownCheck(t *testing.T) {
	cr := models.ControlResult{
		CheckResults: []models.CheckResult{
			{ID: "UNKNOWN-99", Status: models.StatusFail},
		},
	}
	// Unknown checks have no remediation guidance, so they're skipped
	details := BuildRemediationsForControl(cr)
	assert.Empty(t, details)
}
