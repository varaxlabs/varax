package explore

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
)

func TestControlDetailSetControl(t *testing.T) {
	m := newControlDetailModel()
	m.SetSize(100, 40)

	cr := models.ControlResult{
		Control: models.Control{
			ID:          "CC6.1",
			Name:        "Logical Access Controls",
			Description: "Access control policies",
		},
		Status:         models.ControlStatusFail,
		ViolationCount: 2,
		CheckResults: []models.CheckResult{
			{ID: "CIS-5.1.1", Name: "Cluster-admin binding", Status: models.StatusFail, Severity: models.SeverityHigh},
			{ID: "CIS-5.1.2", Name: "Secret access", Status: models.StatusPass, Severity: models.SeverityMedium},
		},
	}

	m.SetControl(cr, nil)

	view := m.View()
	assert.Contains(t, view, "CC6.1")
	assert.Contains(t, view, "Logical Access Controls")
	assert.Contains(t, view, "CIS-5.1.1")
	assert.Contains(t, view, "CIS-5.1.2")
}

func TestControlDetailCursorMovement(t *testing.T) {
	m := newControlDetailModel()
	m.SetSize(100, 40)

	cr := models.ControlResult{
		Control: models.Control{ID: "CC6.1", Name: "Test"},
		CheckResults: []models.CheckResult{
			{ID: "CIS-5.1.1", Name: "Check 1", Status: models.StatusFail},
			{ID: "CIS-5.1.2", Name: "Check 2", Status: models.StatusPass},
		},
	}
	m.SetControl(cr, nil)

	assert.Equal(t, 0, m.checkCursor)

	// Move down
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	assert.Equal(t, 1, m.checkCursor)

	// Don't go past end
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	assert.Equal(t, 1, m.checkCursor)

	// Move up
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	assert.Equal(t, 0, m.checkCursor)

	// Don't go below 0
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	assert.Equal(t, 0, m.checkCursor)
}

func TestControlDetailBackNavigation(t *testing.T) {
	m := newControlDetailModel()
	m.SetSize(100, 40)
	m.SetControl(models.ControlResult{
		Control: models.Control{ID: "CC6.1"},
	}, nil)

	var navMsg navigationMsg
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		msg := cmd()
		navMsg = msg.(navigationMsg)
	}
	assert.Equal(t, viewControls, navMsg.target)
}
