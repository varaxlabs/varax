package explore

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
)

func testData() Data {
	return Data{
		Compliance: &models.ComplianceResult{
			Framework: "SOC2",
			Score:     75.0,
			ControlResults: []models.ControlResult{
				{
					Control: models.Control{
						ID:          "CC6.1",
						Name:        "Logical Access Controls",
						Description: "Test control",
					},
					Status:         models.ControlStatusFail,
					ViolationCount: 2,
					CheckResults: []models.CheckResult{
						{
							ID:       "CIS-5.1.1",
							Name:     "Cluster-admin binding",
							Status:   models.StatusFail,
							Severity: models.SeverityHigh,
						},
						{
							ID:       "CIS-5.1.2",
							Name:     "Secret access",
							Status:   models.StatusPass,
							Severity: models.SeverityMedium,
						},
					},
				},
				{
					Control: models.Control{
						ID:   "CC5.1",
						Name: "Control Activities",
					},
					Status:         models.ControlStatusPass,
					ViolationCount: 0,
				},
			},
		},
		Scan: &models.ScanResult{
			Summary: models.ScanSummary{TotalChecks: 20, PassCount: 15, FailCount: 5},
		},
		HistoricalScores: []float64{60, 65, 70, 75},
	}
}

func TestAppModelNavigation(t *testing.T) {
	data := testData()
	m := newAppModel(data)

	// Initial view is controls
	assert.Equal(t, viewControls, m.currentView)

	// Simulate window size
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 40})
	m = updated.(appModel)
	assert.Equal(t, 80, m.width)
	assert.Equal(t, 40, m.height)

	// Navigate to control detail
	updated, _ = m.Update(navigationMsg{target: viewControlDetail, controlIdx: 0})
	m = updated.(appModel)
	assert.Equal(t, viewControlDetail, m.currentView)
	assert.Equal(t, 0, m.currentControlIdx)

	// Navigate to check detail
	updated, _ = m.Update(navigationMsg{target: viewCheckDetail, checkIdx: 0})
	m = updated.(appModel)
	assert.Equal(t, viewCheckDetail, m.currentView)

	// Navigate back to control detail
	updated, _ = m.Update(navigationMsg{target: viewControlDetail, controlIdx: 0})
	m = updated.(appModel)
	assert.Equal(t, viewControlDetail, m.currentView)

	// Navigate back to controls
	updated, _ = m.Update(navigationMsg{target: viewControls})
	m = updated.(appModel)
	assert.Equal(t, viewControls, m.currentView)
}

func TestAppModelViewRendering(t *testing.T) {
	data := testData()
	m := newAppModel(data)

	// Set size so views can render
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	m = updated.(appModel)

	// Controls view should contain control info
	view := m.View()
	assert.Contains(t, view, "SOC2 Controls")

	// Navigate to control detail and check rendering
	updated, _ = m.Update(navigationMsg{target: viewControlDetail, controlIdx: 0})
	m = updated.(appModel)
	view = m.View()
	assert.Contains(t, view, "CC6.1")
	assert.Contains(t, view, "Logical Access Controls")

	// Navigate to check detail
	updated, _ = m.Update(navigationMsg{target: viewCheckDetail, checkIdx: 0})
	m = updated.(appModel)
	view = m.View()
	assert.Contains(t, view, "CIS-5.1.1")
}

func TestWindowSizePropagation(t *testing.T) {
	data := testData()
	m := newAppModel(data)

	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 50})
	m = updated.(appModel)

	assert.Equal(t, 120, m.controls.width)
	assert.Equal(t, 50, m.controls.height)
	assert.Equal(t, 120, m.controlDetail.width)
	assert.Equal(t, 50, m.controlDetail.height)
	assert.Equal(t, 120, m.checkDetail.width)
	assert.Equal(t, 50, m.checkDetail.height)
}
