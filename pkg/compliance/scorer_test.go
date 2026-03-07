package compliance

import (
	"testing"

	"github.com/varax/operator/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestScorer_AllPass(t *testing.T) {
	results := []models.ControlResult{
		{Status: models.ControlStatusPass},
		{Status: models.ControlStatusPass},
		{Status: models.ControlStatusPass},
	}

	scorer := &Scorer{}
	assert.Equal(t, float64(100), scorer.Calculate(results))
}

func TestScorer_AllFail(t *testing.T) {
	results := []models.ControlResult{
		{Status: models.ControlStatusFail},
		{Status: models.ControlStatusFail},
	}

	scorer := &Scorer{}
	assert.Equal(t, float64(0), scorer.Calculate(results))
}

func TestScorer_Mixed(t *testing.T) {
	results := []models.ControlResult{
		{Status: models.ControlStatusPass},
		{Status: models.ControlStatusFail},
	}

	scorer := &Scorer{}
	assert.Equal(t, float64(50), scorer.Calculate(results))
}

func TestScorer_IgnoresNotAssessed(t *testing.T) {
	results := []models.ControlResult{
		{Status: models.ControlStatusPass},
		{Status: models.ControlStatusNotAssessed},
		{Status: models.ControlStatusNotAssessed},
	}

	scorer := &Scorer{}
	assert.Equal(t, float64(100), scorer.Calculate(results))
}

func TestScorer_AllNotAssessed(t *testing.T) {
	results := []models.ControlResult{
		{Status: models.ControlStatusNotAssessed},
	}

	scorer := &Scorer{}
	assert.Equal(t, float64(0), scorer.Calculate(results))
}

func TestScorer_ProviderManagedCountsAsPass(t *testing.T) {
	// Controls with provider-managed status should be PASS in scoring
	// (derived by mapper), so scorer sees them as ControlStatusPass
	results := []models.ControlResult{
		{Status: models.ControlStatusPass},
		{Status: models.ControlStatusPass},
		{Status: models.ControlStatusFail},
	}

	scorer := &Scorer{}
	// 2 pass out of 3 assessed = 66.67%
	score := scorer.Calculate(results)
	assert.InDelta(t, 66.67, score, 0.1)
}

func TestScorer_Empty(t *testing.T) {
	scorer := &Scorer{}
	assert.Equal(t, float64(0), scorer.Calculate(nil))
}
