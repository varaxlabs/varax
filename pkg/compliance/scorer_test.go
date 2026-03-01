package compliance

import (
	"testing"

	"github.com/kubeshield/operator/pkg/models"
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

func TestScorer_Empty(t *testing.T) {
	scorer := &Scorer{}
	assert.Equal(t, float64(0), scorer.Calculate(nil))
}
