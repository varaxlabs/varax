package explore

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/varax/operator/pkg/reports"
)

// Run starts the interactive explore TUI.
func Run(data Data) error {
	m := newAppModel(data)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

type appModel struct {
	data          Data
	currentView   viewID
	controls      controlsModel
	controlDetail controlDetailModel
	checkDetail   checkDetailModel
	width, height int
	// Track which control index we're viewing so we can return to it
	currentControlIdx int
}

func newAppModel(data Data) appModel {
	return appModel{
		data:          data,
		currentView:   viewControls,
		controls:      newControlsModel(&data),
		controlDetail: newControlDetailModel(),
		checkDetail:   newCheckDetailModel(),
	}
}

func (m appModel) Init() tea.Cmd {
	return nil
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.controls.SetSize(msg.Width, msg.Height)
		m.controlDetail.SetSize(msg.Width, msg.Height)
		m.checkDetail.SetSize(msg.Width, msg.Height)
		return m, nil

	case navigationMsg:
		return m.handleNavigation(msg)
	}

	// Delegate to current view
	switch m.currentView {
	case viewControls:
		var cmd tea.Cmd
		m.controls, cmd = m.controls.Update(msg)
		return m, cmd
	case viewControlDetail:
		var cmd tea.Cmd
		m.controlDetail, cmd = m.controlDetail.Update(msg)
		return m, cmd
	case viewCheckDetail:
		var cmd tea.Cmd
		m.checkDetail, cmd = m.checkDetail.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m appModel) handleNavigation(msg navigationMsg) (tea.Model, tea.Cmd) {
	switch msg.target {
	case viewControls:
		m.currentView = viewControls
	case viewControlDetail:
		m.currentControlIdx = msg.controlIdx
		cr := m.data.Compliance.ControlResults[msg.controlIdx]
		ev := reports.FilterEvidenceForControl(m.data.Evidence, cr.Control.ID)
		m.controlDetail.SetControl(cr, ev)
		m.currentView = viewControlDetail
	case viewCheckDetail:
		if msg.checkIdx < len(m.data.Compliance.ControlResults[m.currentControlIdx].CheckResults) {
			check := m.data.Compliance.ControlResults[m.currentControlIdx].CheckResults[msg.checkIdx]
			m.checkDetail.SetCheck(check)
			m.currentView = viewCheckDetail
		}
	}
	return m, nil
}

func (m appModel) View() string {
	switch m.currentView {
	case viewControls:
		return m.controls.View()
	case viewControlDetail:
		return m.controlDetail.View()
	case viewCheckDetail:
		return m.checkDetail.View()
	default:
		return ""
	}
}
