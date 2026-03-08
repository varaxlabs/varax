package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/remediation"
)

func testReport() *remediation.RemediationReport {
	return &remediation.RemediationReport{
		ID:        "test-1",
		ScanID:    "scan-1",
		Timestamp: time.Now(),
		Duration:  2 * time.Second,
		DryRun:    true,
		Results: []remediation.RemediationResult{
			{
				Action: remediation.RemediationAction{
					CheckID: "CIS-5.2.2", ActionType: remediation.ActionPatch,
					TargetKind: "Deployment", TargetName: "web", Field: "securityContext.runAsNonRoot",
				},
				Status: remediation.StatusDryRun,
			},
			{
				Action: remediation.RemediationAction{
					CheckID: "CIS-5.2.1", ActionType: remediation.ActionPatch,
					TargetKind: "Pod", TargetName: "api", Field: "securityContext.allowPrivilegeEscalation",
				},
				Status:     remediation.StatusSkipped,
				SkipReason: remediation.SkipSystemNamespace,
			},
			{
				Action: remediation.RemediationAction{
					CheckID: "CIS-5.2.3", ActionType: remediation.ActionPatch,
					TargetKind: "Pod", TargetName: "worker", Field: "securityContext.privileged",
				},
				Status: remediation.StatusFailed,
				Error:  "patch conflict",
			},
			{
				Action: remediation.RemediationAction{
					CheckID: "CIS-5.2.4", ActionType: remediation.ActionPatch,
					TargetKind: "Pod", TargetName: "svc", Field: "securityContext.capabilities",
				},
				Status: remediation.StatusApplied,
			},
		},
		Summary: remediation.RemediationSummary{
			TotalActions: 4, AppliedCount: 1, DryRunCount: 1, SkippedCount: 1, FailedCount: 1,
		},
	}
}

func TestRemediationBox(t *testing.T) {
	out := RemediationBox(testReport())
	assert.Contains(t, out, "Remediation Report")
	assert.Contains(t, out, "DRY RUN")
	assert.Contains(t, out, "4 total")
	assert.Contains(t, out, "CIS-5.2.2")
}

func TestRemediationBoxPlain(t *testing.T) {
	out := RemediationBoxPlain(testReport())
	assert.Contains(t, out, "Remediation Report")
	assert.Contains(t, out, "DRY RUN")
	assert.Contains(t, out, "4 total")
	assert.Contains(t, out, "CIS-5.2.1")
	assert.Contains(t, out, "system-namespace")
	assert.Contains(t, out, "patch conflict")
}

func TestRemediationBox_LiveMode(t *testing.T) {
	r := testReport()
	r.DryRun = false
	out := RemediationBox(r)
	assert.Contains(t, out, "LIVE")
}

func TestRemediationBoxPlain_NoResults(t *testing.T) {
	r := &remediation.RemediationReport{
		Duration: time.Second,
		Summary:  remediation.RemediationSummary{TotalActions: 0},
	}
	out := RemediationBoxPlain(r)
	assert.Contains(t, out, "0 total")
	assert.NotContains(t, out, "CIS-")
}
