package reports

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/evidence"
)

func TestEvidenceCategoriesForControl(t *testing.T) {
	tests := []struct {
		controlID  string
		expected   []string
	}{
		{"CC6.1", []string{"RBAC"}},
		{"CC6.6", []string{"Network"}},
		{"CC7.1", []string{"Audit"}},
		{"CC8.1", []string{"Encryption"}},
		{"CC5.1", []string{"RBAC", "Encryption"}},
		{"A1.1", []string{"Network"}},
		{"UNKNOWN", nil},
	}
	for _, tt := range tests {
		result := evidenceCategoriesForControl(tt.controlID)
		assert.Equal(t, tt.expected, result, "controlID: %s", tt.controlID)
	}
}

func TestAllSOC2ControlsHaveMapping(t *testing.T) {
	knownControls := []string{
		"CC5.1", "CC5.2", "CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.7", "CC6.8",
		"CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5", "CC8.1", "A1.1", "A1.2",
	}
	for _, id := range knownControls {
		cats := evidenceCategoriesForControl(id)
		assert.NotNil(t, cats, "control %s should have evidence mapping", id)
		assert.NotEmpty(t, cats, "control %s should have at least one category", id)
	}
}

func TestFilterEvidenceForControl(t *testing.T) {
	bundle := &evidence.EvidenceBundle{
		CollectedAt: time.Now(),
		Items: []evidence.EvidenceItem{
			{Category: "RBAC", Description: "ClusterRoles"},
			{Category: "Network", Description: "NetworkPolicies"},
			{Category: "Audit", Description: "AuditLogs"},
			{Category: "Encryption", Description: "Secrets"},
			{Category: "RBAC", Description: "RoleBindings"},
		},
	}

	// CC6.1 maps to RBAC
	rbacItems := FilterEvidenceForControl(bundle, "CC6.1")
	assert.Len(t, rbacItems, 2)
	assert.Equal(t, "RBAC", rbacItems[0].Category)
	assert.Equal(t, "RBAC", rbacItems[1].Category)

	// CC6.6 maps to Network
	netItems := FilterEvidenceForControl(bundle, "CC6.6")
	assert.Len(t, netItems, 1)
	assert.Equal(t, "Network", netItems[0].Category)

	// CC5.1 maps to RBAC + Encryption
	multiItems := FilterEvidenceForControl(bundle, "CC5.1")
	assert.Len(t, multiItems, 3)

	// Unknown control
	assert.Nil(t, FilterEvidenceForControl(bundle, "UNKNOWN"))

	// Nil bundle
	assert.Nil(t, FilterEvidenceForControl(nil, "CC6.1"))
}
