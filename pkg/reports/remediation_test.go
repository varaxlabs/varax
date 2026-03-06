package reports

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemediation_KnownCheckIDs(t *testing.T) {
	tests := []struct {
		id       string
		contains string
	}{
		{"CIS-1.2.1", "RBAC"},
		{"CIS-1.2.14", "anonymous"},
		{"CIS-4.2.1", "anonymous"},
		{"CIS-5.2.1", "allowPrivilegeEscalation"},
		{"CIS-5.7.1", "resource limits"},
		{"NSA-PS-1", "non-root"},
		{"PSS-1.1", "Baseline"},
		{"RBAC-1", "ClusterRoleBindings"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			result := Remediation(tt.id)
			assert.NotEmpty(t, result, "expected remediation for %s", tt.id)
			assert.Contains(t, result, tt.contains)
		})
	}
}

func TestRemediation_UnknownCheckID(t *testing.T) {
	assert.Empty(t, Remediation("UNKNOWN-99"))
	assert.Empty(t, Remediation(""))
}

func TestRemediation_AllEntriesNonEmpty(t *testing.T) {
	for id, text := range remediations {
		assert.NotEmpty(t, id, "found empty key in remediations map")
		assert.NotEmpty(t, text, "empty remediation for %s", id)
	}
}
