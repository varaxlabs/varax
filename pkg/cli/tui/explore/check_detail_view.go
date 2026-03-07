package explore

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/reports"
)

type checkDetailModel struct {
	viewport viewport.Model
	check    models.CheckResult
	width    int
	height   int
	ready    bool
}

func newCheckDetailModel() checkDetailModel {
	return checkDetailModel{}
}

func (m *checkDetailModel) SetCheck(cr models.CheckResult) {
	m.check = cr
	m.updateContent()
}

func (m *checkDetailModel) updateContent() {
	var b strings.Builder

	b.WriteString(headerStyle.Render(fmt.Sprintf("%s — %s", m.check.ID, m.check.Name)))
	b.WriteString("\n\n")

	fmt.Fprintf(&b, "%s %s\n", labelStyle.Render("Status:"), statusBadge(string(m.check.Status)))
	fmt.Fprintf(&b, "%s %s\n", labelStyle.Render("Severity:"), severityBadge(string(m.check.Severity)))
	fmt.Fprintf(&b, "%s %s\n", labelStyle.Render("Benchmark:"), m.check.Benchmark)

	if m.check.Description != "" {
		fmt.Fprintf(&b, "\n%s %s\n", labelStyle.Render("Description:"), m.check.Description)
	}

	if m.check.Message != "" {
		fmt.Fprintf(&b, "\n%s %s\n", labelStyle.Render("Message:"), m.check.Message)
	}

	// Evidence
	if len(m.check.Evidence) > 0 {
		b.WriteString("\n")
		b.WriteString(headerStyle.Render("Evidence"))
		b.WriteString("\n")
		for _, ev := range m.check.Evidence {
			var parts []string
			if ev.Resource.Kind != "" {
				res := ev.Resource.Kind + "/" + ev.Resource.Name
				if ev.Resource.Namespace != "" {
					res = ev.Resource.Namespace + "/" + res
				}
				parts = append(parts, res)
			}
			if ev.Field != "" {
				parts = append(parts, fmt.Sprintf("%s=%s", ev.Field, ev.Value))
			}

			detail := ""
			if len(parts) > 0 {
				detail = " [" + strings.Join(parts, ", ") + "]"
			}
			b.WriteString(evidenceBlockStyle.Render(fmt.Sprintf("%s%s", ev.Message, detail)))
			b.WriteString("\n")
		}
	}

	// Remediation
	if rem := reports.Remediation(m.check.ID); rem != "" {
		b.WriteString("\n")
		b.WriteString(headerStyle.Render("Remediation"))
		b.WriteString("\n")
		b.WriteString(remediationBlockStyle.Render(rem))
		b.WriteString("\n")
	}

	if m.ready {
		m.viewport.SetContent(b.String())
	}
}

func (m checkDetailModel) Init() tea.Cmd {
	return nil
}

func (m checkDetailModel) Update(msg tea.Msg) (checkDetailModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Back):
			return m, func() tea.Msg {
				return navigationMsg{target: viewControlDetail}
			}
		case key.Matches(msg, keys.Quit):
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m checkDetailModel) View() string {
	if !m.ready {
		return "Loading..."
	}

	help := statusBarStyle.Render("  esc: back  |  q: quit")
	return m.viewport.View() + "\n" + help
}

func (m *checkDetailModel) SetSize(w, h int) {
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
