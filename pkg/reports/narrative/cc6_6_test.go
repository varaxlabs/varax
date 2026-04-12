package narrative

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildCC6_6_AllDeny(t *testing.T) {
	raw := CC6_6Raw{
		TotalPolicies:          15,
		NamespacesWithPolicies: 5,
		TotalNamespaces:        5,
		NamespacesWithDeny:     5,
		CoveragePercent:        100,
		PassCount:              3,
		FailCount:              0,
	}
	n := BuildCC6_6(raw)
	assert.Contains(t, n.CoverageSummary, "15 NetworkPolicies")
	assert.Contains(t, n.CoverageSummary, "5 namespaces")
	assert.Contains(t, n.DefaultDenySummary, "all 5 namespaces")
	assert.Contains(t, n.DefaultDenySummary, "zero-trust")
	assert.Empty(t, n.GapSummary)
	assert.Contains(t, n.AssessmentStatement, "PASS")
}

func TestBuildCC6_6_PartialDeny(t *testing.T) {
	raw := CC6_6Raw{
		TotalPolicies:          8,
		TotalNamespaces:        5,
		NamespacesWithDeny:     3,
		NamespacesWithoutDeny:  []string{"staging", "dev"},
		PassCount:              2,
		FailCount:              1,
	}
	n := BuildCC6_6(raw)
	assert.Contains(t, n.DefaultDenySummary, "3 namespaces")
	assert.Contains(t, n.GapSummary, "staging")
	assert.Contains(t, n.GapSummary, "dev")
	assert.Contains(t, n.AssessmentStatement, "PARTIAL")
}

func TestBuildCC6_6_NoDeny(t *testing.T) {
	raw := CC6_6Raw{
		TotalNamespaces:       3,
		NamespacesWithDeny:    0,
		NamespacesWithoutDeny: []string{"app", "staging", "dev"},
		PassCount:             0,
		FailCount:             2,
	}
	n := BuildCC6_6(raw)
	assert.Contains(t, n.DefaultDenySummary, "No namespaces")
	assert.Contains(t, n.DefaultDenySummary, "lateral movement")
	assert.Contains(t, n.AssessmentStatement, "FAIL")
}

func TestBuildCC6_6_ManyGaps(t *testing.T) {
	gaps := make([]string, 12)
	for i := range gaps {
		gaps[i] = "ns-" + string(rune('a'+i))
	}
	raw := CC6_6Raw{
		TotalNamespaces:       15,
		NamespacesWithDeny:    3,
		NamespacesWithoutDeny: gaps,
		PassCount:             1,
		FailCount:             1,
	}
	n := BuildCC6_6(raw)
	assert.Contains(t, n.GapSummary, "12 namespaces lack")
}

func TestBuildCC6_6_SingleNamespace(t *testing.T) {
	raw := CC6_6Raw{
		TotalPolicies:     1,
		TotalNamespaces:   1,
		NamespacesWithDeny: 1,
		PassCount:         1,
	}
	n := BuildCC6_6(raw)
	assert.Contains(t, n.CoverageSummary, "1 NetworkPolicy")
	assert.Contains(t, n.CoverageSummary, "1 namespace")
	assert.Contains(t, n.DefaultDenySummary, "1 namespace")
}

func TestBuildCC6_6_WithFindings(t *testing.T) {
	raw := CC6_6Raw{
		TotalNamespaces: 3,
		PassCount:       1,
		FailCount:       1,
		Findings: []Finding{
			{CheckID: "CIS-5.3.2", Severity: "HIGH", Message: "No default deny policy"},
		},
	}
	n := BuildCC6_6(raw)
	assert.Len(t, n.Findings, 1)
}

func TestCC6_6Narrative_Sections(t *testing.T) {
	raw := CC6_6Raw{
		TotalPolicies:     5,
		TotalNamespaces:   3,
		NamespacesWithDeny: 3,
		PassCount:         2,
		FailCount:         1,
		Findings: []Finding{
			{CheckID: "CIS-5.3.2", Severity: "HIGH", Message: "test"},
		},
	}
	n := BuildCC6_6(raw)
	sections := n.Sections()
	assert.GreaterOrEqual(t, len(sections), 3)
}
