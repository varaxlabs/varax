package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScoreTrend_Empty(t *testing.T) {
	assert.Equal(t, "No history available", ScoreTrend(nil))
}

func TestScoreTrend_SingleScore(t *testing.T) {
	result := ScoreTrend([]float64{78})
	assert.Contains(t, result, "Score: 78%")
	assert.Contains(t, result, "Trend:")
	assert.NotContains(t, result, "from last scan")
}

func TestScoreTrend_Increasing(t *testing.T) {
	result := ScoreTrend([]float64{72, 75, 78})
	assert.Contains(t, result, "Score: 78%")
	assert.Contains(t, result, "+3 from last scan")
}

func TestScoreTrend_Decreasing(t *testing.T) {
	result := ScoreTrend([]float64{80, 75})
	assert.Contains(t, result, "Score: 75%")
	assert.Contains(t, result, "-5 from last scan")
}

func TestScoreTrend_NoChange(t *testing.T) {
	result := ScoreTrend([]float64{80, 80})
	assert.Contains(t, result, "Score: 80%")
	assert.Contains(t, result, "no change")
}

func TestScoreTrendPlain_Empty(t *testing.T) {
	assert.Equal(t, "No history available", ScoreTrendPlain(nil))
}

func TestScoreTrendPlain_Increasing(t *testing.T) {
	result := ScoreTrendPlain([]float64{72, 75, 78})
	assert.Contains(t, result, "Score: 78%")
	assert.Contains(t, result, "(^ +3 from last scan)")
	assert.Contains(t, result, "Trend: [72, 75, 78]")
}

func TestScoreTrendPlain_Decreasing(t *testing.T) {
	result := ScoreTrendPlain([]float64{80, 75})
	assert.Contains(t, result, "(v -5 from last scan)")
}

func TestSparkline(t *testing.T) {
	// Just verify it doesn't panic and returns something
	result := sparkline([]float64{0, 25, 50, 75, 100})
	assert.NotEmpty(t, result)
}

func TestSparkline_Empty(t *testing.T) {
	assert.Empty(t, sparkline(nil))
}

func TestPlainSparkline(t *testing.T) {
	assert.Equal(t, "72, 75, 78", plainSparkline([]float64{72, 75, 78}))
}
