package compliance

import (
	"testing"
	"time"

	"github.com/varax/operator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allCheckIDs() []string {
	return []string{
		"CIS-5.1.1", "CIS-5.1.2", "CIS-5.1.3", "CIS-5.1.5", "CIS-5.1.6", "CIS-5.1.8",
		"CIS-5.2.1", "CIS-5.2.2", "CIS-5.2.3", "CIS-5.2.4", "CIS-5.2.5", "CIS-5.2.6",
		"CIS-5.2.7", "CIS-5.2.8", "CIS-5.2.13",
		"CIS-5.3.2",
		"CIS-5.4.1",
		"CIS-5.7.2", "CIS-5.7.3", "CIS-5.7.4",
	}
}

func TestMapper_AllPass(t *testing.T) {
	var results []models.CheckResult
	for _, id := range allCheckIDs() {
		results = append(results, models.CheckResult{ID: id, Status: models.StatusPass})
	}

	scanResult := &models.ScanResult{
		ID:        "test-scan",
		Timestamp: time.Now(),
		Results:   results,
	}

	mapper := NewSOC2Mapper()
	result := mapper.MapResults(scanResult)

	require.NotNil(t, result)
	assert.Equal(t, "SOC2", result.Framework)
	assert.Equal(t, float64(100), result.Score)

	// Count assessed controls — all 9 should now be assessed
	assessed := 0
	for _, cr := range result.ControlResults {
		if cr.Status != models.ControlStatusNotAssessed {
			assessed++
			assert.Equal(t, models.ControlStatusPass, cr.Status)
		}
	}
	assert.Equal(t, 9, assessed)
}

func TestMapper_AllFail(t *testing.T) {
	var results []models.CheckResult
	for _, id := range allCheckIDs() {
		results = append(results, models.CheckResult{ID: id, Status: models.StatusFail, Evidence: []models.Evidence{{Message: "fail"}}})
	}

	scanResult := &models.ScanResult{
		ID:        "test-scan",
		Timestamp: time.Now(),
		Results:   results,
	}

	mapper := NewSOC2Mapper()
	result := mapper.MapResults(scanResult)

	assert.Equal(t, float64(0), result.Score)
}

func TestMapper_MixedResults(t *testing.T) {
	scanResult := &models.ScanResult{
		ID:        "test-scan",
		Timestamp: time.Now(),
		Results: []models.CheckResult{
			{ID: "CIS-5.1.1", Status: models.StatusPass},
			{ID: "CIS-5.1.2", Status: models.StatusPass},
			{ID: "CIS-5.1.3", Status: models.StatusFail, Evidence: []models.Evidence{{Message: "fail"}}},
			{ID: "CIS-5.1.5", Status: models.StatusPass},
			{ID: "CIS-5.1.6", Status: models.StatusPass},
			{ID: "CIS-5.1.8", Status: models.StatusPass},
			{ID: "CIS-5.2.1", Status: models.StatusPass},
			{ID: "CIS-5.2.2", Status: models.StatusPass},
			{ID: "CIS-5.2.3", Status: models.StatusPass},
			{ID: "CIS-5.2.4", Status: models.StatusPass},
			{ID: "CIS-5.2.5", Status: models.StatusPass},
			{ID: "CIS-5.2.6", Status: models.StatusPass},
			{ID: "CIS-5.2.7", Status: models.StatusPass},
			{ID: "CIS-5.2.8", Status: models.StatusPass},
			{ID: "CIS-5.2.13", Status: models.StatusPass},
			{ID: "CIS-5.3.2", Status: models.StatusPass},
			{ID: "CIS-5.4.1", Status: models.StatusPass},
			{ID: "CIS-5.7.2", Status: models.StatusPass},
			{ID: "CIS-5.7.3", Status: models.StatusPass},
			{ID: "CIS-5.7.4", Status: models.StatusPass},
		},
	}

	mapper := NewSOC2Mapper()
	result := mapper.MapResults(scanResult)

	// CC6.1 maps to 5.1.1 (pass) + 5.1.3 (fail) + 5.1.8 (pass) → PARTIAL
	// CC6.3 maps to 5.1.1 (pass) + 5.1.3 (fail) + 5.1.8 (pass) → PARTIAL
	assert.True(t, result.Score > 0 && result.Score < 100)
}

func TestMapper_ProviderManagedAsPass(t *testing.T) {
	var results []models.CheckResult
	for _, id := range allCheckIDs() {
		results = append(results, models.CheckResult{ID: id, Status: models.StatusProviderManaged})
	}

	scanResult := &models.ScanResult{
		ID:        "test-scan",
		Timestamp: time.Now(),
		Results:   results,
	}

	mapper := NewSOC2Mapper()
	result := mapper.MapResults(scanResult)

	require.NotNil(t, result)
	assert.Equal(t, float64(100), result.Score)

	for _, cr := range result.ControlResults {
		if cr.Status != models.ControlStatusNotAssessed {
			assert.Equal(t, models.ControlStatusPass, cr.Status)
		}
	}
}

func TestMapper_MixedProviderManagedAndFail(t *testing.T) {
	scanResult := &models.ScanResult{
		ID:        "test-scan",
		Timestamp: time.Now(),
		Results: []models.CheckResult{
			{ID: "CIS-5.1.1", Status: models.StatusProviderManaged},
			{ID: "CIS-5.1.2", Status: models.StatusPass},
			{ID: "CIS-5.1.3", Status: models.StatusFail, Evidence: []models.Evidence{{Message: "fail"}}},
			{ID: "CIS-5.1.5", Status: models.StatusPass},
			{ID: "CIS-5.1.6", Status: models.StatusPass},
			{ID: "CIS-5.1.8", Status: models.StatusProviderManaged},
		},
	}

	mapper := NewSOC2Mapper()
	result := mapper.MapResults(scanResult)

	// CC6.1 maps to 5.1.1 (provider-managed) + 5.1.3 (fail) + 5.1.8 (provider-managed) → PARTIAL
	assert.True(t, result.Score > 0 && result.Score < 100)
}

func TestMapper_NotAssessedControls(t *testing.T) {
	scanResult := &models.ScanResult{
		ID:        "test-scan",
		Timestamp: time.Now(),
		Results:   []models.CheckResult{},
	}

	mapper := NewSOC2Mapper()
	result := mapper.MapResults(scanResult)

	assert.Equal(t, float64(0), result.Score)
	for _, cr := range result.ControlResults {
		assert.Equal(t, models.ControlStatusNotAssessed, cr.Status)
	}
}
