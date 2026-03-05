package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/varax/operator/pkg/models"
)

// progressMsg is sent for each completed check.
type progressMsg struct {
	Completed int
	Total     int
	Current   models.CheckResult
}

// doneMsg signals scan completion.
type doneMsg struct {
	Result *models.ScanResult
	Err    error
}

type scanModel struct {
	completed  int
	total      int
	current    string
	startTime  time.Time
	spinner    spinner.Model
	finished   bool
	scanResult *models.ScanResult
	err        error
	progressCh <-chan progressMsg
	doneCh     <-chan doneMsg
	passCount  int
	failCount  int
	skipCount  int
}

func newScanModel(progressCh <-chan progressMsg, doneCh <-chan doneMsg) scanModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	return scanModel{
		spinner:    s,
		startTime:  time.Now(),
		progressCh: progressCh,
		doneCh:     doneCh,
	}
}

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(
		waitForProgress(m.progressCh),
		waitForDone(m.doneCh),
		m.spinner.Tick,
	)
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case progressMsg:
		m.completed = msg.Completed
		m.total = msg.Total
		m.current = msg.Current.Name
		switch msg.Current.Status {
		case models.StatusPass:
			m.passCount++
		case models.StatusFail:
			m.failCount++
		case models.StatusSkip:
			m.skipCount++
		}
		return m, waitForProgress(m.progressCh)

	case doneMsg:
		m.finished = true
		m.scanResult = msg.Result
		m.err = msg.Err
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m scanModel) View() string {
	if m.finished {
		return ""
	}

	var b strings.Builder

	b.WriteString(fmt.Sprintf("\n  Scanning cluster...  %s\n\n", m.spinner.View()))

	// Progress bar
	if m.total > 0 {
		b.WriteString(fmt.Sprintf("  %s %d/%d checks", progressBar(m.completed, m.total, 30), m.completed, m.total))
		if m.completed > 0 {
			eta := estimateETA(m.startTime, m.completed, m.total)
			b.WriteString(fmt.Sprintf("  ETA: %s", formatDuration(eta)))
		}
		b.WriteString("\n\n")
	}

	if m.current != "" {
		b.WriteString(fmt.Sprintf("  Current: %s\n\n", m.current))
	}

	b.WriteString(fmt.Sprintf("  pass: %d  fail: %d  skip: %d\n", m.passCount, m.failCount, m.skipCount))

	return b.String()
}

func progressBar(completed, total, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := completed * width / total
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func estimateETA(start time.Time, completed, total int) time.Duration {
	if completed == 0 {
		return 0
	}
	elapsed := time.Since(start)
	rate := elapsed / time.Duration(completed)
	remaining := time.Duration(total-completed) * rate
	return remaining
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm %ds", m, s)
}

func waitForProgress(ch <-chan progressMsg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

func waitForDone(ch <-chan doneMsg) tea.Cmd {
	return func() tea.Msg {
		return <-ch
	}
}
