package explore

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
)

func TestControlItemRendering(t *testing.T) {
	item := controlItem{
		control: models.ControlResult{
			Control: models.Control{
				ID:   "CC6.1",
				Name: "Logical Access Controls",
			},
			Status:         models.ControlStatusFail,
			ViolationCount: 3,
		},
	}

	assert.Contains(t, item.Title(), "CC6.1")
	assert.Contains(t, item.Title(), "Logical Access Controls")
	assert.Contains(t, item.Description(), "FAIL")
	assert.Contains(t, item.Description(), "3 violation(s)")
	assert.Contains(t, item.FilterValue(), "CC6.1")
}

func TestControlItemNoViolations(t *testing.T) {
	item := controlItem{
		control: models.ControlResult{
			Control: models.Control{ID: "CC5.1", Name: "Control Activities"},
			Status:  models.ControlStatusPass,
		},
	}

	assert.Contains(t, item.Description(), "PASS")
	assert.NotContains(t, item.Description(), "violation")
}

func TestFilterCycling(t *testing.T) {
	data := testData()
	m := newControlsModel(&data)
	m.SetSize(100, 40)

	// Start with all
	assert.Equal(t, filterAll, m.currentFilter)

	// Cycle through filters
	m.currentFilter = filterPass
	m.rebuildList()
	items := m.list.Items()
	for _, item := range items {
		ci := item.(controlItem)
		assert.Equal(t, models.ControlStatusPass, ci.control.Status)
	}

	m.currentFilter = filterFail
	m.rebuildList()
	items = m.list.Items()
	for _, item := range items {
		ci := item.(controlItem)
		assert.Equal(t, models.ControlStatusFail, ci.control.Status)
	}
}

func TestControlsInit(t *testing.T) {
	data := testData()
	m := newControlsModel(&data)
	assert.Nil(t, m.Init())
}

func TestControlsUpdateEnter(t *testing.T) {
	data := testData()
	m := newControlsModel(&data)
	m.SetSize(100, 40)

	// Press enter — should produce a navigation message
	m, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		msg := cmd()
		nav, ok := msg.(navigationMsg)
		if ok {
			assert.Equal(t, viewControlDetail, nav.target)
		}
	}
	_ = m
}

func TestControlsUpdateFilter(t *testing.T) {
	data := testData()
	m := newControlsModel(&data)
	m.SetSize(100, 40)

	// Press 'f' to cycle filter
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	assert.Equal(t, filterPass, m.currentFilter)

	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	assert.Equal(t, filterFail, m.currentFilter)
}

func TestControlsUpdateQuit(t *testing.T) {
	data := testData()
	m := newControlsModel(&data)
	m.SetSize(100, 40)

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	assert.NotNil(t, cmd)
}

func TestMatchesFilterPartial(t *testing.T) {
	data := testData()
	m := newControlsModel(&data)
	m.currentFilter = filterPartial
	cr := models.ControlResult{Status: models.ControlStatusPartial}
	assert.True(t, m.matchesFilter(cr))
	cr2 := models.ControlResult{Status: models.ControlStatusPass}
	assert.False(t, m.matchesFilter(cr2))
}

func TestControlsViewContainsScore(t *testing.T) {
	data := testData()
	m := newControlsModel(&data)
	m.SetSize(100, 40)

	view := m.View()
	assert.Contains(t, view, "Score:")
}
