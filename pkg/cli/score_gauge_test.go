package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScoreGaugePlain(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		want  string
	}{
		{"zero", 0, "[--------------------] 0/100"},
		{"half", 50, "[##########----------] 50/100"},
		{"full", 100, "[####################] 100/100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScoreGaugePlain(tt.score)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestScoreGauge_ContainsScore(t *testing.T) {
	result := ScoreGauge(75)
	assert.Contains(t, result, "75/100")
}
