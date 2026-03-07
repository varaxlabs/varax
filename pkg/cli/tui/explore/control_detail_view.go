package explore

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/reports"
)

type controlDetailModel struct {
	viewport    viewport.Model
	control     models.ControlResult
	evidence    []evidence.EvidenceItem
	checkCursor int
	width       int
	height      int
	ready       bool
}

func newControlDetailModel() controlDetailModel {
	return controlDetailModel{}
}

func (m *controlDetailModel) SetControl(cr models.ControlResult, ev []evidence.EvidenceItem) {
	m.control = cr
	m.evidence = ev
	m.checkCursor = 0
	m.updateContent()
}

func (m *controlDetailModel) updateContent() {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render(fmt.Sprintf("%s — %s", m.control.Control.ID, m.control.Control.Name)))
	b.WriteString("\n\n")

	// Status and description
	fmt.Fprintf(&b, "%s %s\n\n", labelStyle.Render("Status:"), statusBadge(string(m.control.Status)))
	if m.control.Control.Description != "" {
		fmt.Fprintf(&b, "%s %s\n\n", labelStyle.Render("Description:"), m.control.Control.Description)
	}
	fmt.Fprintf(&b, "%s %d\n\n", labelStyle.Render("Violations:"), m.control.ViolationCount)

	// Check results
	b.WriteString(headerStyle.Render("Mapped Checks"))
	b.WriteString("\n")

	for i, cr := range m.control.CheckResults {
		prefix := "  "
		if i == m.checkCursor {
			prefix = selectedRowStyle.Render("> ")
		}

		statusStr := string(cr.Status)
		sev := string(cr.Severity)
		fmt.Fprintf(&b, "%s%-12s %-8s %-8s %s\n", prefix, cr.ID, statusStr, sev, cr.Name)

		// Show evidence for selected check
		if i == m.checkCursor && len(cr.Evidence) > 0 {
			for _, ev := range cr.Evidence {
				fmt.Fprintf(&b, "    - %s\n", ev.Message)
			}
		}
	}

	// Evidence items
	if len(m.evidence) > 0 {
		b.WriteString("\n")
		b.WriteString(headerStyle.Render("Evidence"))
		b.WriteString("\n")
		for _, item := range m.evidence {
			block := fmt.Sprintf("[%s] %s", item.Category, item.Description)
			b.WriteString(evidenceBlockStyle.Render(block))
			b.WriteString("\n")
		}
	}

	// Remediation for selected check
	if len(m.control.CheckResults) > 0 && m.checkCursor < len(m.control.CheckResults) {
		check := m.control.CheckResults[m.checkCursor]
		if rem := reports.Remediation(check.ID); rem != "" {
			b.WriteString("\n")
			b.WriteString(remediationBlockStyle.Render(fmt.Sprintf("Remediation: %s", rem)))
			b.WriteString("\n")
		}
	}

	if m.ready {
		m.viewport.SetContent(b.String())
	}
}

func (m controlDetailModel) Init() tea.Cmd {
	return nil
}

func (m controlDetailModel) Update(msg tea.Msg) (controlDetailModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Back):
			return m, func() tea.Msg {
				return navigationMsg{target: viewControls}
			}
		case key.Matches(msg, keys.Enter):
			if len(m.control.CheckResults) > 0 {
				return m, func() tea.Msg {
					return navigationMsg{target: viewCheckDetail, checkIdx: m.checkCursor}
				}
			}
		case key.Matches(msg, keys.Quit):
			return m, tea.Quit
		case msg.String() == "j" || msg.String() == "down":
			if m.checkCursor < len(m.control.CheckResults)-1 {
				m.checkCursor++
				m.updateContent()
			}
			return m, nil
		case msg.String() == "k" || msg.String() == "up":
			if m.checkCursor > 0 {
				m.checkCursor--
				m.updateContent()
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m controlDetailModel) View() string {
	if !m.ready {
		return "Loading..."
	}

	help := statusBarStyle.Render("  j/k: navigate checks  |  enter: check detail  |  esc: back  |  q: quit")
	return m.viewport.View() + "\n" + help
}

func (m *controlDetailModel) SetSize(w, h int) {
	m.width = w
	m.height = h
	if !m.ready {
		m.viewport = viewport.New(w, h-3)
		m.ready = true
	} else {
		m.viewport.Width = w
		m.viewport.Height = h - 3
	}
	m.updateContent()
}
