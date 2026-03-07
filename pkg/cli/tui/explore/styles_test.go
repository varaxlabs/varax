package explore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatusBadge(t *testing.T) {
	cases := []struct {
		input    string
		contains string
	}{
		{"PASS", "PASS"},
		{"FAIL", "FAIL"},
		{"PARTIAL", "PARTIAL"},
		{"UNKNOWN", "N/A"},
	}
	for _, tc := range cases {
		assert.Contains(t, statusBadge(tc.input), tc.contains)
	}
}

func TestSeverityBadge(t *testing.T) {
	cases := []struct {
		input    string
		contains string
	}{
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
		{"INFO", "INFO"},
	}
	for _, tc := range cases {
		assert.Contains(t, severityBadge(tc.input), tc.contains)
	}
}
