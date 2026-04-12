package narrative

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildCC7_1_ManagedCluster(t *testing.T) {
	raw := CC7_1Raw{
		IsManagedCluster: true,
		PassCount:        3,
		FailCount:        0,
	}
	n := BuildCC7_1(raw)
	assert.Contains(t, n.AuditLoggingSummary, "managed Kubernetes cluster")
	assert.Contains(t, n.AuditLoggingSummary, "cloud provider")
	assert.Empty(t, n.ConfigDetails)
	assert.Contains(t, n.AssessmentStatement, "PASS")
}

func TestBuildCC7_1_SelfManaged_FullConfig(t *testing.T) {
	raw := CC7_1Raw{
		APIServerFound:  true,
		AuditLogPath:    "/var/log/kubernetes/audit.log",
		AuditPolicyFile: "/etc/kubernetes/audit-policy.yaml",
		AuditMaxAge:     "30",
		PassCount:       4,
		FailCount:       0,
	}
	n := BuildCC7_1(raw)
	assert.Contains(t, n.AuditLoggingSummary, "/var/log/kubernetes/audit.log")
	assert.Contains(t, n.ConfigDetails, "audit-policy.yaml")
	assert.Contains(t, n.ConfigDetails, "30 days")
	assert.Contains(t, n.AssessmentStatement, "PASS")
}

func TestBuildCC7_1_SelfManaged_NoAudit(t *testing.T) {
	raw := CC7_1Raw{
		APIServerFound: true,
		PassCount:      0,
		FailCount:      3,
	}
	n := BuildCC7_1(raw)
	assert.Contains(t, n.AuditLoggingSummary, "audit logging is not configured")
	assert.Contains(t, n.AuditLoggingSummary, "significant gap")
	assert.Contains(t, n.AssessmentStatement, "FAIL")
}

func TestBuildCC7_1_NoAPIServer(t *testing.T) {
	raw := CC7_1Raw{
		APIServerFound: false,
		PassCount:      1,
		FailCount:      1,
	}
	n := BuildCC7_1(raw)
	assert.Contains(t, n.AuditLoggingSummary, "could not be directly inspected")
}

func TestBuildCC7_1_PartialConfig(t *testing.T) {
	raw := CC7_1Raw{
		APIServerFound: true,
		AuditLogPath:   "/var/log/audit.log",
		PassCount:      2,
		FailCount:      1,
	}
	n := BuildCC7_1(raw)
	assert.Contains(t, n.AuditLoggingSummary, "/var/log/audit.log")
	assert.Empty(t, n.ConfigDetails)
}

func TestBuildCC7_1_WithFindings(t *testing.T) {
	raw := CC7_1Raw{
		IsManagedCluster: true,
		PassCount:        2,
		FailCount:        1,
		Findings: []Finding{
			{CheckID: "CIS-3.2.1", Severity: "HIGH", Message: "audit policy missing"},
		},
	}
	n := BuildCC7_1(raw)
	assert.Len(t, n.Findings, 1)
}

func TestCC7_1Narrative_Sections(t *testing.T) {
	raw := CC7_1Raw{
		IsManagedCluster: true,
		PassCount:        2,
		FailCount:        1,
		Findings: []Finding{
			{CheckID: "CIS-3.2.1", Severity: "HIGH", Message: "test"},
		},
	}
	n := BuildCC7_1(raw)
	sections := n.Sections()
	assert.GreaterOrEqual(t, len(sections), 2)
}
