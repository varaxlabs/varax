package narrative

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPluralize(t *testing.T) {
	assert.Equal(t, "1 binding", pluralize(1, "binding", "bindings"))
	assert.Equal(t, "0 bindings", pluralize(0, "binding", "bindings"))
	assert.Equal(t, "3 bindings", pluralize(3, "binding", "bindings"))
	assert.Equal(t, "1 ClusterRole", pluralize(1, "ClusterRole", "ClusterRoles"))
	assert.Equal(t, "47 ClusterRoles", pluralize(47, "ClusterRole", "ClusterRoles"))
}

func TestJoinList(t *testing.T) {
	assert.Equal(t, "", joinList(nil))
	assert.Equal(t, "", joinList([]string{}))
	assert.Equal(t, "alpha", joinList([]string{"alpha"}))
	assert.Equal(t, "alpha and beta", joinList([]string{"alpha", "beta"}))
	assert.Equal(t, "alpha, beta, and gamma", joinList([]string{"alpha", "beta", "gamma"}))
	assert.Equal(t, "a, b, c, and d", joinList([]string{"a", "b", "c", "d"}))
}

func TestVerbAgreement(t *testing.T) {
	assert.Equal(t, "has", verbAgreement(1))
	assert.Equal(t, "have", verbAgreement(0))
	assert.Equal(t, "have", verbAgreement(2))
	assert.Equal(t, "have", verbAgreement(100))
}

func TestPercent(t *testing.T) {
	assert.Equal(t, 50, percent(50, 100))
	assert.Equal(t, 0, percent(0, 100))
	assert.Equal(t, 100, percent(100, 100))
	assert.Equal(t, 0, percent(5, 0)) // zero total
	assert.Equal(t, 33, percent(1, 3))
}

func TestStatusLabel(t *testing.T) {
	assert.Equal(t, "PASS", statusLabel(5, 0))
	assert.Equal(t, "FAIL", statusLabel(0, 3))
	assert.Equal(t, "PARTIAL", statusLabel(5, 2))
	assert.Equal(t, "NOT ASSESSED", statusLabel(0, 0))
}

func TestCountByStatus(t *testing.T) {
	assert.Equal(t, "5 checks passing", countByStatus(5, 0))
	assert.Equal(t, "3 checks failing", countByStatus(0, 3))
	assert.Equal(t, "5 checks passing and 2 checks failing", countByStatus(5, 2))
	assert.Equal(t, "1 check passing and 1 check failing", countByStatus(1, 1))
	assert.Equal(t, "no checks assessed", countByStatus(0, 0))
}

func TestMinimalNarrative(t *testing.T) {
	n := MinimalNarrative{
		Summary:    "This control covers incident response.",
		Assessment: "Assessment: PASS",
	}
	sections := n.Sections()
	assert.Len(t, sections, 2)
	assert.Equal(t, "This control covers incident response.", sections[0].Body)
	assert.Equal(t, "Assessment: PASS", sections[1].Body)
}

func TestMinimalNarrative_Empty(t *testing.T) {
	n := MinimalNarrative{}
	assert.Empty(t, n.Sections())
}

func TestFindingsSection_Corroboration(t *testing.T) {
	findings := []Finding{
		{CheckID: "CIS-5.1.3", Message: "2 ClusterRoles use wildcard resources: legacy-admin, dev-full-access"},
		{CheckID: "RBAC-3", Message: "2 ClusterRoles use wildcard: legacy-admin, dev-full-access"},
	}
	section := findingsSection(findings)
	assert.Len(t, section.Items, 1) // grouped into one
	assert.Contains(t, section.Items[0], "CIS-5.1.3")
	assert.Contains(t, section.Items[0], "RBAC-3")
	assert.Contains(t, section.Items[0], "2 independent checks confirm this finding")
}

func TestFindingsSection_NoCorroboration(t *testing.T) {
	findings := []Finding{
		{CheckID: "CIS-5.1.3", Message: "2 ClusterRoles use wildcard resources"},
		{CheckID: "CIS-5.3.2", Message: "3 namespaces missing NetworkPolicy"},
	}
	section := findingsSection(findings)
	assert.Len(t, section.Items, 2) // separate findings
	assert.NotContains(t, section.Items[0], "independent checks")
}

func TestFindingsSection_Empty(t *testing.T) {
	section := findingsSection(nil)
	assert.Empty(t, section.Items)
}
