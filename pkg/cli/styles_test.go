package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatusBadge_Pass(t *testing.T) {
	result := StatusBadge("PASS")
	assert.Contains(t, result, "PASS")
}

func TestStatusBadge_Fail(t *testing.T) {
	result := StatusBadge("FAIL")
	assert.Contains(t, result, "FAIL")
}

func TestStatusBadge_Partial(t *testing.T) {
	result := StatusBadge("PARTIAL")
	assert.Contains(t, result, "PARTIAL")
}

func TestStatusBadge_Unknown(t *testing.T) {
	result := StatusBadge("UNKNOWN")
	assert.Contains(t, result, "N/A")
}

func TestStatusBadge_Empty(t *testing.T) {
	result := StatusBadge("")
	assert.Contains(t, result, "N/A")
}
