package reports

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
)

func TestStatusClass(t *testing.T) {
	tests := []struct {
		input    models.CheckStatus
		expected string
	}{
		{models.StatusPass, "status-pass"},
		{models.StatusFail, "status-fail"},
		{models.StatusWarn, "status-warn"},
		{models.StatusSkip, "status-skip"},
		{"UNKNOWN", "status-unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, statusClass(tt.input))
	}
}

func TestControlStatusClass(t *testing.T) {
	tests := []struct {
		input    models.ControlStatus
		expected string
	}{
		{models.ControlStatusPass, "status-pass"},
		{models.ControlStatusFail, "status-fail"},
		{models.ControlStatusPartial, "status-partial"},
		{models.ControlStatusNotAssessed, "status-na"},
		{"UNKNOWN", "status-unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, controlStatusClass(tt.input))
	}
}

func TestSeverityClass(t *testing.T) {
	tests := []struct {
		input    models.Severity
		expected string
	}{
		{models.SeverityCritical, "severity-critical"},
		{models.SeverityHigh, "severity-high"},
		{models.SeverityMedium, "severity-medium"},
		{models.SeverityLow, "severity-low"},
		{models.SeverityInfo, "severity-info"},
		{"UNKNOWN", "severity-unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, severityClass(tt.input))
	}
}

func TestFormatTime(t *testing.T) {
	ts := time.Date(2026, 3, 5, 14, 30, 0, 0, time.UTC)
	assert.Equal(t, "2026-03-05 14:30:00 UTC", formatTime(ts))
	assert.Equal(t, "N/A", formatTime(time.Time{}))
}

func TestFormatDate(t *testing.T) {
	ts := time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, "March 5, 2026", formatDate(ts))
	assert.Equal(t, "N/A", formatDate(time.Time{}))
}

func TestFormatScore(t *testing.T) {
	assert.Equal(t, "85%", formatScore(85.0))
	assert.Equal(t, "0%", formatScore(0.0))
	assert.Equal(t, "100%", formatScore(100.0))
}

func TestScoreClass(t *testing.T) {
	assert.Equal(t, "score-high", scoreClass(80.0))
	assert.Equal(t, "score-high", scoreClass(100.0))
	assert.Equal(t, "score-medium", scoreClass(50.0))
	assert.Equal(t, "score-medium", scoreClass(79.9))
	assert.Equal(t, "score-low", scoreClass(49.9))
	assert.Equal(t, "score-low", scoreClass(0.0))
}

func TestJsonPretty(t *testing.T) {
	assert.Equal(t, "{}", jsonPretty(nil))
	result := jsonPretty(map[string]string{"key": "value"})
	assert.Contains(t, result, "key")
	assert.Contains(t, result, "value")
}

func TestSeq(t *testing.T) {
	assert.Nil(t, seq(0))
	assert.Nil(t, seq(-1))
	assert.Equal(t, []int{0, 1, 2}, seq(3))
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hel...", truncate("hello world", 6))
	assert.Equal(t, "he", truncate("hello", 2))
}

func TestTemplateFuncs(t *testing.T) {
	funcs := templateFuncs()
	assert.NotNil(t, funcs["statusClass"])
	assert.NotNil(t, funcs["severityClass"])
	assert.NotNil(t, funcs["formatTime"])
	assert.NotNil(t, funcs["formatDate"])
	assert.NotNil(t, funcs["formatScore"])
	assert.NotNil(t, funcs["scoreClass"])
	assert.NotNil(t, funcs["jsonPretty"])
	assert.NotNil(t, funcs["add"])
	assert.NotNil(t, funcs["sub"])
	assert.NotNil(t, funcs["seq"])
	assert.NotNil(t, funcs["upper"])
	assert.NotNil(t, funcs["css"])
	assert.NotNil(t, funcs["controlStatusClass"])
	assert.NotNil(t, funcs["truncate"])

	// Test add/sub via FuncMap
	addFn := funcs["add"].(func(int, int) int)
	assert.Equal(t, 5, addFn(2, 3))
	subFn := funcs["sub"].(func(int, int) int)
	assert.Equal(t, 1, subFn(3, 2))
}
