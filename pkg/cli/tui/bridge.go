package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
)

// RunScanWithTUI runs the scan with an animated TUI progress display.
// Returns the scan result and compliance result after the TUI exits.
func RunScanWithTUI(ctx context.Context, runner *scanning.ScanRunner, mapper *compliance.Mapper) (*models.ScanResult, *models.ComplianceResult, error) {
	progressCh := make(chan progressMsg, 10)
	doneCh := make(chan doneMsg, 1)

	// Run scan in background goroutine
	go func() {
		defer close(progressCh)
		result, err := runner.RunAll(ctx, func(completed, total int, current models.CheckResult) {
			progressCh <- progressMsg{
				Completed: completed,
				Total:     total,
				Current:   current,
			}
		})
		doneCh <- doneMsg{Result: result, Err: err}
	}()

	// Run TUI
	m := newScanModel(progressCh, doneCh)
	p := tea.NewProgram(m)
	finalModel, err := p.Run()
	if err != nil {
		return nil, nil, err
	}

	fm := finalModel.(scanModel)
	if fm.err != nil {
		return nil, nil, fm.err
	}

	scanResult := fm.scanResult
	complianceResult := mapper.MapResults(scanResult)

	return scanResult, complianceResult, nil
}
