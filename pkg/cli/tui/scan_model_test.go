package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
)

func TestProgressBar(t *testing.T) {
	assert.Equal(t, "██████████████████████████████", progressBar(10, 10, 30))
	assert.Equal(t, "███████████████░░░░░░░░░░░░░░░", progressBar(5, 10, 30))
	assert.Equal(t, "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░", progressBar(0, 10, 30))
	assert.Equal(t, "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░", progressBar(0, 0, 30))
}

func TestEstimateETA(t *testing.T) {
	start := time.Now().Add(-10 * time.Second)
	eta := estimateETA(start, 5, 10)
	// Should be approximately 10 seconds (half done in 10s)
	assert.InDelta(t, 10, eta.Seconds(), 2)
}

func TestEstimateETA_ZeroCompleted(t *testing.T) {
	start := time.Now()
	eta := estimateETA(start, 0, 10)
	assert.Equal(t, time.Duration(0), eta)
}

func TestFormatDuration(t *testing.T) {
	assert.Equal(t, "<1s", formatDuration(500*time.Millisecond))
	assert.Equal(t, "30s", formatDuration(30*time.Second))
	assert.Equal(t, "1m 30s", formatDuration(90*time.Second))
}

func TestScanModelUpdate_Progress(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)

	// Send a progress message
	newModel, _ := m.Update(progressMsg{
		Completed: 5,
		Total:     10,
		Current:   models.CheckResult{Name: "Test Check", Status: models.StatusPass},
	})

	sm := newModel.(scanModel)
	assert.Equal(t, 5, sm.completed)
	assert.Equal(t, 10, sm.total)
	assert.Equal(t, "Test Check", sm.current)
	assert.Equal(t, 1, sm.passCount)
}

func TestScanModelUpdate_Done(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)

	scanResult := &models.ScanResult{ID: "test"}
	newModel, _ := m.Update(doneMsg{Result: scanResult})

	sm := newModel.(scanModel)
	assert.True(t, sm.finished)
	assert.Equal(t, "test", sm.scanResult.ID)
}

func TestScanModelView(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)
	m.total = 10
	m.completed = 5
	m.current = "Test Check"
	m.passCount = 3
	m.failCount = 1
	m.skipCount = 1

	view := m.View()
	assert.Contains(t, view, "Scanning cluster...")
	assert.Contains(t, view, "5/10 checks")
	assert.Contains(t, view, "Test Check")
	assert.Contains(t, view, "pass: 3")
	assert.Contains(t, view, "fail: 1")
}

func TestScanModelView_Finished(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)
	m.finished = true

	view := m.View()
	assert.Equal(t, "", view)
}

func TestScanModel_Init(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)
	cmd := m.Init()
	require.NotNil(t, cmd)
}

func TestScanModelUpdate_KeyCtrlC(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	// tea.Quit is a Cmd (function), so it should be non-nil
	require.NotNil(t, cmd)
}

func TestScanModelUpdate_KeyQ(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	require.NotNil(t, cmd)
}

func TestScanModelUpdate_UnknownMsg(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)

	type unknownMsg struct{}
	newModel, cmd := m.Update(unknownMsg{})
	assert.Nil(t, cmd)

	sm := newModel.(scanModel)
	assert.Equal(t, 0, sm.completed)
	assert.Equal(t, 0, sm.total)
	assert.False(t, sm.finished)
}

func TestWaitForProgress_ClosedChannel(t *testing.T) {
	ch := make(chan progressMsg)
	close(ch)

	cmd := waitForProgress(ch)
	msg := cmd()
	assert.Nil(t, msg)
}

func TestWaitForDone(t *testing.T) {
	ch := make(chan doneMsg, 1)
	expected := doneMsg{Result: &models.ScanResult{ID: "test-done"}}
	ch <- expected

	cmd := waitForDone(ch)
	msg := cmd()
	result, ok := msg.(doneMsg)
	require.True(t, ok)
	assert.Equal(t, "test-done", result.Result.ID)
}

func TestProgressBar_CompletedGreaterThanTotal(t *testing.T) {
	// Edge case: completed > total should clamp to full bar
	bar := progressBar(15, 10, 30)
	assert.Equal(t, "██████████████████████████████", bar)
}

func TestScanModelView_TotalZero(t *testing.T) {
	progressCh := make(chan progressMsg, 1)
	doneCh := make(chan doneMsg, 1)

	m := newScanModel(progressCh, doneCh)
	m.total = 0

	view := m.View()
	assert.Contains(t, view, "Scanning cluster...")
	assert.NotContains(t, view, "checks")
}
