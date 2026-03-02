package cli

import (
	"testing"

	"github.com/varax/operator/pkg/models"
	"github.com/stretchr/testify/assert"
)

func makeTestControlResults() []models.ControlResult {
	return []models.ControlResult{
		{
			Control:        models.Control{ID: "CC6.1", Name: "Logical Access Controls"},
			Status:         models.ControlStatusPass,
			ViolationCount: 0,
		},
		{
			Control:        models.Control{ID: "CC6.2", Name: "Authentication Mechanisms"},
			Status:         models.ControlStatusFail,
			ViolationCount: 5,
		},
		{
			Control:        models.Control{ID: "CC7.1", Name: "Monitoring and Detection"},
			Status:         models.ControlStatusPartial,
			ViolationCount: 2,
		},
	}
}

func TestControlTable_ContainsHeaders(t *testing.T) {
	results := makeTestControlResults()
	output := ControlTable(results)

	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "Control")
	assert.Contains(t, output, "Status")
	assert.Contains(t, output, "Violations")
}

func TestControlTable_ContainsControlData(t *testing.T) {
	results := makeTestControlResults()
	output := ControlTable(results)

	assert.Contains(t, output, "CC6.1")
	assert.Contains(t, output, "CC6.2")
	assert.Contains(t, output, "CC7.1")
	assert.Contains(t, output, "Logical Access Controls")
}

func TestControlTablePlain_ContainsHeaders(t *testing.T) {
	results := makeTestControlResults()
	output := ControlTablePlain(results)

	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "Control")
	assert.Contains(t, output, "Status")
	assert.Contains(t, output, "Violations")
}

func TestControlTablePlain_ContainsControlData(t *testing.T) {
	results := makeTestControlResults()
	output := ControlTablePlain(results)

	assert.Contains(t, output, "CC6.1")
	assert.Contains(t, output, "PASS")
	assert.Contains(t, output, "CC6.2")
	assert.Contains(t, output, "FAIL")
	assert.Contains(t, output, "5")
}

func TestControlTablePlain_EmptyResults(t *testing.T) {
	output := ControlTablePlain([]models.ControlResult{})
	// Should still have headers
	assert.Contains(t, output, "ID")
}

func TestTruncate_Short(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
}

func TestTruncate_Exact(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 5))
}

func TestTruncate_Long(t *testing.T) {
	assert.Equal(t, "hell...", truncate("hello world", 7))
}
