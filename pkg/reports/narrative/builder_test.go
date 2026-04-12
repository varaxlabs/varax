package narrative

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
)

func TestBuildAll_SkipsNotAssessed(t *testing.T) {
	controls := []models.ControlResult{
		{
			Control: models.Control{ID: "CC7.3", Name: "Evaluate Security Events"},
			Status:  models.ControlStatusNotAssessed,
		},
	}
	result := BuildAll(controls, nil)
	assert.Empty(t, result)
}

func TestBuildAll_MinimalControls(t *testing.T) {
	controls := []models.ControlResult{
		{
			Control: models.Control{ID: "CC7.3", Name: "Evaluate Security Events"},
			Status:  models.ControlStatusPass,
			CheckResults: []models.CheckResult{
				{ID: "CIS-5.2.3", Status: models.StatusPass, Message: "No privileged containers"},
			},
		},
		{
			Control: models.Control{ID: "CC7.4", Name: "Respond to Security Incidents"},
			Status:  models.ControlStatusFail,
			CheckResults: []models.CheckResult{
				{ID: "CIS-1.2.9", Status: models.StatusFail, Message: "Event rate limit not configured"},
			},
		},
	}

	result := BuildAll(controls, nil)
	assert.Len(t, result, 2)

	// CC7.3 should have a full narrative
	cc73 := result["CC7.3"]
	assert.NotNil(t, cc73)
	sections := cc73.Sections()
	assert.NotEmpty(t, sections)
	assert.Contains(t, sections[0].Body, "evaluates detected security events")

	// CC7.4 should have findings
	cc74 := result["CC7.4"]
	assert.NotNil(t, cc74)
	sections = cc74.Sections()
	found := false
	for _, s := range sections {
		if s.Body != "" {
			found = true
		}
	}
	assert.True(t, found)
}

func TestBuildAll_AllControls(t *testing.T) {
	// Verify that BuildAll produces a narrative for every assessed control
	controlIDs := []string{
		"CC5.1", "CC5.2", "CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.7", "CC6.8",
		"CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5", "CC8.1", "A1.1", "A1.2",
	}

	var controls []models.ControlResult
	for _, id := range controlIDs {
		controls = append(controls, models.ControlResult{
			Control: models.Control{ID: id, Name: "Test Control"},
			Status:  models.ControlStatusPass,
			CheckResults: []models.CheckResult{
				{ID: "TEST-1", Status: models.StatusPass, Message: "test passed"},
			},
		})
	}

	result := BuildAll(controls, nil)
	assert.Len(t, result, 16)

	for _, id := range controlIDs {
		n, ok := result[id]
		assert.True(t, ok, "missing narrative for %s", id)
		assert.NotNil(t, n, "nil narrative for %s", id)
		sections := n.Sections()
		assert.NotEmpty(t, sections, "empty sections for %s", id)
	}
}
