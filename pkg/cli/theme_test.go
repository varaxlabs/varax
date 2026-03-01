package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveFormat_Explicit(t *testing.T) {
	assert.Equal(t, FormatJSON, ResolveFormat("json"))
	assert.Equal(t, FormatPlain, ResolveFormat("plain"))
	assert.Equal(t, FormatStyled, ResolveFormat("styled"))
}

func TestResolveFormat_Default(t *testing.T) {
	// In test context, stdout is not a TTY
	result := ResolveFormat("")
	assert.Equal(t, FormatPlain, result)
}
