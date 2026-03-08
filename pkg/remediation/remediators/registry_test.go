package remediators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/remediation"
)

func TestRegisterAll(t *testing.T) {
	reg := remediation.NewRemediatorRegistry()
	RegisterAll(reg)

	// Verify all remediators are registered by checking known check IDs
	checkIDs := []string{
		"CIS-5.2.1", "CIS-5.2.2", "CIS-5.2.3", "CIS-5.2.4", "CIS-5.7.2",
		"CIS-5.2.5", "CIS-5.2.6", "CIS-5.2.7",
		"CIS-5.1.6", "CIS-5.3.2", "CIS-5.7.1",
	}
	for _, id := range checkIDs {
		r := reg.Get(id)
		assert.NotNil(t, r, "expected remediator for %s", id)
	}
}
