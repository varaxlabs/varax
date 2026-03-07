package explore

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
)

func TestCheckDetailSetCheck(t *testing.T) {
	m := newCheckDetailModel()
	m.SetSize(100, 40)

	cr := models.CheckResult{
		ID:          "CIS-5.1.1",
		Name:        "Cluster-admin binding",
		Description: "Ensure cluster-admin role is used minimally",
		Benchmark:   "CIS",
		Severity:    models.SeverityHigh,
		Status:      models.StatusFail,
		Message:     "Found 3 cluster-admin bindings",
		Evidence: []models.Evidence{
			{
				Message:  "ClusterRoleBinding admin-binding grants cluster-admin",
				Resource: models.Resource{Kind: "ClusterRoleBinding", Name: "admin-binding"},
			},
		},
	}

	m.SetCheck(cr)

	view := m.View()
	assert.Contains(t, view, "CIS-5.1.1")
	assert.Contains(t, view, "Cluster-admin binding")
	assert.Contains(t, view, "CIS")
	assert.Contains(t, view, "ClusterRoleBinding")
}

func TestCheckDetailRemediation(t *testing.T) {
	m := newCheckDetailModel()
	m.SetSize(100, 40)

	m.SetCheck(models.CheckResult{
		ID:     "CIS-5.1.1",
		Name:   "Cluster-admin binding",
		Status: models.StatusFail,
	})

	view := m.View()
	assert.Contains(t, view, "Remediation")
	assert.Contains(t, view, "cluster-admin ClusterRoleBindings")
}

func TestCheckDetailBackNavigation(t *testing.T) {
	m := newCheckDetailModel()
	m.SetSize(100, 40)
	m.SetCheck(models.CheckResult{ID: "CIS-5.1.1"})

	var navMsg navigationMsg
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		msg := cmd()
		navMsg = msg.(navigationMsg)
	}
	assert.Equal(t, viewControlDetail, navMsg.target)
}
