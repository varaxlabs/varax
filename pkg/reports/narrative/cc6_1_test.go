package narrative

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildCC6_1_FullCluster(t *testing.T) {
	raw := CC6_1Raw{
		TotalClusterRoles: 47,
		TotalCRBs:         23,
		TotalRoleBindings: 116,
		NamespaceScopedCount: 93,
		NamespaceScopedPercent: 80,
		ClusterAdminCount: 2,
		ClusterAdminBindings: []BindingDetail{
			{Name: "system:masters-binding", Subject: "system:masters", Type: "Group"},
			{Name: "eks-admin", Subject: "break-glass-admin", Type: "User"},
		},
		NamespacesAudited: 12,
		AutoMountCount:    0,
		PassCount:         5,
		FailCount:         2,
		Findings: []Finding{
			{CheckID: "CIS-5.1.3", Severity: "HIGH", Message: "2 ClusterRoles use wildcard resources"},
		},
	}

	n := BuildCC6_1(raw)

	assert.Contains(t, n.AccessControlSummary, "47 ClusterRoles")
	assert.Contains(t, n.AccessControlSummary, "23 ClusterRoleBindings")
	assert.Contains(t, n.AccessControlSummary, "2 authorized bindings")
	assert.Contains(t, n.AccessControlSummary, "system:masters (Group)")
	assert.Contains(t, n.AccessControlSummary, "break-glass-admin (User)")
	assert.Contains(t, n.AccessControlSummary, "organization enforces logical access controls")
	assert.Contains(t, n.ScopingSummary, "80%")
	assert.Contains(t, n.ScopingSummary, "93 of 116")
	assert.Contains(t, n.TokenMountSummary, "12 audited namespaces")
	assert.Contains(t, n.TokenMountSummary, "disabled")
	require.Len(t, n.Findings, 1)
	assert.Equal(t, "CIS-5.1.3", n.Findings[0].CheckID)
	assert.Contains(t, n.AssessmentStatement, "PARTIAL")
}

func TestBuildCC6_1_SingleBinding(t *testing.T) {
	raw := CC6_1Raw{
		TotalClusterRoles: 12,
		TotalCRBs:         5,
		ClusterAdminCount: 1,
		ClusterAdminBindings: []BindingDetail{
			{Subject: "system:masters", Type: "Group"},
		},
		NamespacesAudited: 3,
		PassCount:         4,
		FailCount:         0,
	}
	n := BuildCC6_1(raw)
	assert.Contains(t, n.AccessControlSummary, "1 authorized binding")
	assert.NotContains(t, n.AccessControlSummary, "authorized bindings")
	assert.Contains(t, n.AccessControlSummary, "system:masters (Group)")
	assert.Contains(t, n.AssessmentStatement, "PASS")
}

func TestBuildCC6_1_NoFindings(t *testing.T) {
	raw := CC6_1Raw{PassCount: 5, FailCount: 0}
	n := BuildCC6_1(raw)
	assert.Empty(t, n.Findings)
	assert.Contains(t, n.AssessmentStatement, "PASS")
}

func TestBuildCC6_1_MultipleAutoMounts(t *testing.T) {
	raw := CC6_1Raw{
		NamespacesAudited: 5,
		AutoMountCount:    3,
		PassCount:         2,
		FailCount:         1,
	}
	n := BuildCC6_1(raw)
	assert.Contains(t, n.TokenMountSummary, "3 service accounts")
	assert.Contains(t, n.TokenMountSummary, "have")
}

func TestBuildCC6_1_SingleAutoMount(t *testing.T) {
	raw := CC6_1Raw{
		NamespacesAudited: 1,
		AutoMountCount:    1,
		PassCount:         1,
		FailCount:         1,
	}
	n := BuildCC6_1(raw)
	assert.Contains(t, n.TokenMountSummary, "1 service account")
	assert.Contains(t, n.TokenMountSummary, "has")
}

func TestBuildCC6_1_OIDC(t *testing.T) {
	raw := CC6_1Raw{OIDCConfigured: true, PassCount: 1}
	n := BuildCC6_1(raw)
	assert.Contains(t, n.AuthSummary, "OIDC")
}

func TestCC6_1Narrative_Sections(t *testing.T) {
	raw := CC6_1Raw{
		TotalClusterRoles: 10,
		TotalCRBs:         5,
		NamespacesAudited: 3,
		PassCount:         3,
		FailCount:         0,
	}
	n := BuildCC6_1(raw)
	sections := n.Sections()
	// Should have at least AccessControlSummary, TokenMountSummary, AssessmentStatement
	assert.GreaterOrEqual(t, len(sections), 3)
	for _, s := range sections {
		assert.NotEmpty(t, s.Body)
	}
}
