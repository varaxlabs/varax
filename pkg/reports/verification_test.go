package reports

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommandsForControl_CC6_1(t *testing.T) {
	cmds := CommandsForControl("CC6.1")
	assert.NotEmpty(t, cmds)

	// Should include RBAC and SA token mount commands
	descriptions := make([]string, len(cmds))
	for i, cmd := range cmds {
		descriptions[i] = cmd.Description
		assert.NotEmpty(t, cmd.Command)
	}
	assert.Contains(t, descriptions, "Count cluster-admin bindings")
	assert.Contains(t, descriptions, "List service accounts with auto-mount enabled")
}

func TestCommandsForControl_CC6_6(t *testing.T) {
	cmds := CommandsForControl("CC6.6")
	assert.NotEmpty(t, cmds)

	descriptions := make([]string, len(cmds))
	for i, cmd := range cmds {
		descriptions[i] = cmd.Description
	}
	assert.Contains(t, descriptions, "List namespaces without NetworkPolicies")
}

func TestCommandsForControl_CC7_1(t *testing.T) {
	cmds := CommandsForControl("CC7.1")
	assert.NotEmpty(t, cmds)

	descriptions := make([]string, len(cmds))
	for i, cmd := range cmds {
		descriptions[i] = cmd.Description
	}
	assert.Contains(t, descriptions, "Verify audit logging configuration (self-hosted)")
}

func TestCommandsForControl_Unknown(t *testing.T) {
	cmds := CommandsForControl("UNKNOWN")
	assert.Nil(t, cmds)
}

func TestCommandsForControl_NoDuplicates(t *testing.T) {
	cmds := CommandsForControl("CC6.1")
	seen := make(map[string]bool)
	for _, cmd := range cmds {
		assert.False(t, seen[cmd.Description], "duplicate command: %s", cmd.Description)
		seen[cmd.Description] = true
	}
}

func TestAllVerificationCommandsHaveContent(t *testing.T) {
	for artType, cmds := range verificationCommands {
		for _, cmd := range cmds {
			assert.NotEmpty(t, cmd.Description, "empty description for artifact type %s", artType)
			assert.NotEmpty(t, cmd.Command, "empty command for artifact type %s", artType)
		}
	}
}
