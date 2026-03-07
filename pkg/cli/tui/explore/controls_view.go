package explore

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/varax/operator/pkg/cli"
	"github.com/varax/operator/pkg/models"
)

type statusFilter int

const (
	filterAll statusFilter = iota
	filterPass
	filterFail
	filterPartial
)

var statusFilterLabels = []string{"All", "Pass", "Fail", "Partial"}

type controlItem struct {
	control models.ControlResult
	idx     int
}

func (i controlItem) Title() string {
	return fmt.Sprintf("%s  %s", i.control.Control.ID, i.control.Control.Name)
}

func (i controlItem) Description() string {
	violations := ""
	if i.control.ViolationCount > 0 {
		violations = fmt.Sprintf("  %d violation(s)", i.control.ViolationCount)
	}
	return fmt.Sprintf("%s%s", string(i.control.Status), violations)
}

func (i controlItem) FilterValue() string {
	return i.control.Control.ID + " " + i.control.Control.Name
}

type controlsModel struct {
	list             list.Model
	data             *Data
	width, height    int
	currentFilter    statusFilter
	allControls      []models.ControlResult
}

func newControlsModel(data *Data) controlsModel {
	m := controlsModel{
		data:        data,
		allControls: data.Compliance.ControlResults,
	}
	m.rebuildList()
	return m
}

func (m *controlsModel) rebuildList() {
	var items []list.Item
	for i, cr := range m.allControls {
		if m.matchesFilter(cr) {
			items = append(items, controlItem{control: cr, idx: i})
		}
	}

	delegate := list.NewDefaultDelegate()
	l := list.New(items, delegate, m.width, m.height-6)
	l.Title = "SOC2 Controls"
	l.SetShowHelp(false)
	l.SetFilteringEnabled(true)
	m.list = l
}

func (m *controlsModel) matchesFilter(cr models.ControlResult) bool {
	switch m.currentFilter {
	case filterPass:
		return cr.Status == models.ControlStatusPass
	case filterFail:
		return cr.Status == models.ControlStatusFail
	case filterPartial:
		return cr.Status == models.ControlStatusPartial
	default:
		return true
	}
}

func (m controlsModel) Init() tea.Cmd {
	return nil
}

func (m controlsModel) Update(msg tea.Msg) (controlsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Don't handle custom keys while filtering
		if m.list.FilterState() == list.Filtering {
			break
		}

		switch {
		case key.Matches(msg, keys.Enter):
			item, ok := m.list.SelectedItem().(controlItem)
			if ok {
				return m, func() tea.Msg {
					return navigationMsg{target: viewControlDetail, controlIdx: item.idx}
				}
			}
		case key.Matches(msg, keys.Filter):
			m.currentFilter = (m.currentFilter + 1) % 4
			m.rebuildList()
			return m, nil
		case key.Matches(msg, keys.Quit):
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m controlsModel) View() string {
	var b strings.Builder

	// Score gauge at top
	if m.data.Compliance != nil {
		gauge := cli.ScoreGauge(m.data.Compliance.Score)
		b.WriteString(fmt.Sprintf("  Score: %s\n", gauge))
	}

	b.WriteString(m.list.View())

	// Status bar
	filterLabel := statusFilterLabels[m.currentFilter]
	help := lipgloss.NewStyle().Foreground(colorGray).Render(
		fmt.Sprintf("  filter: %s (f)  |  enter: details  |  /: search  |  q: quit", filterLabel),
	)
	b.WriteString("\n" + help)

	return b.String()
}

func (m *controlsModel) SetSize(w, h int) {
	m.width = w
	m.height = h
	m.list.SetSize(w, h-6)
}
