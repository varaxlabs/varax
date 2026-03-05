package main

import (
	"fmt"
	"time"

	"github.com/varax/operator/pkg/cli"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/storage"
	"github.com/spf13/cobra"
)

var (
	statusHistory    int
	statusControls   bool
	statusEvidence   bool
	statusBenchmark  string
)

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the latest stored compliance scan results",
		RunE:  runStatus,
	}
	cmd.Flags().IntVar(&statusHistory, "history", 0, "show last N scan results with score trend")
	cmd.Flags().BoolVar(&statusControls, "controls", false, "show detailed per-control breakdown")
	cmd.Flags().BoolVar(&statusEvidence, "evidence", false, "show latest evidence bundle summary")
	cmd.Flags().StringVar(&statusBenchmark, "benchmark", "", "filter results by benchmark (CIS, NSA-CISA, PSS, RBAC)")
	return cmd
}

func runStatus(cmd *cobra.Command, args []string) error {
	store, err := storage.NewBoltStore(defaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer store.Close()

	format := cli.ResolveFormat(outputFormat)

	// History mode: show score trend
	if statusHistory > 0 {
		return showHistory(store, format)
	}

	scanResult, err := store.GetLatestScanResult()
	if err != nil {
		return fmt.Errorf("failed to read latest scan: %w", err)
	}
	if scanResult == nil {
		fmt.Println("No scan results found. Run 'varax scan' first.")
		return nil
	}

	// Filter by benchmark if specified
	if statusBenchmark != "" {
		scanResult = filterByBenchmark(scanResult, statusBenchmark)
	}

	mapper := compliance.NewSOC2Mapper()
	complianceResult := mapper.MapResults(scanResult)

	switch format {
	case cli.FormatJSON:
		output := map[string]any{
			"scan":       scanResult,
			"compliance": complianceResult,
		}
		if statusEvidence {
			bundle, evErr := store.GetLatestEvidenceBundle()
			if evErr == nil && bundle != nil {
				output["evidence"] = bundle
			}
		}
		return cli.RenderJSON(output)
	case cli.FormatPlain:
		fmt.Println(cli.SummaryBoxPlain(complianceResult, scanResult))
		if statusControls {
			fmt.Println(cli.ControlTablePlain(complianceResult.ControlResults))
		}
	default:
		fmt.Println(cli.SummaryBox(complianceResult, scanResult))
		if statusControls {
			fmt.Println(cli.ControlTable(complianceResult.ControlResults))
		}
	}

	// Evidence summary
	if statusEvidence {
		bundle, evErr := store.GetLatestEvidenceBundle()
		if evErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not read evidence: %v\n", evErr)
		} else if bundle != nil {
			fmt.Printf("\n  Evidence: %d items collected at %s\n", len(bundle.Items), bundle.CollectedAt.Format(time.RFC3339))
		} else {
			fmt.Println("\n  No evidence bundles found. Run 'varax scan --evidence' to collect.")
		}
	}

	return nil
}

func showHistory(store storage.Store, format cli.OutputFormat) error {
	results, err := store.ListScanResults(statusHistory)
	if err != nil {
		return fmt.Errorf("failed to list scan results: %w", err)
	}
	if len(results) == 0 {
		fmt.Println("No scan history found. Run 'varax scan' first.")
		return nil
	}

	mapper := compliance.NewSOC2Mapper()

	// Collect scores in chronological order (ListScanResults returns reverse-chronological)
	scores := make([]float64, len(results))
	for i, r := range results {
		r := r
		cr := mapper.MapResults(&r)
		scores[len(results)-1-i] = cr.Score
	}

	switch format {
	case cli.FormatJSON:
		history := make([]map[string]any, len(results))
		for i, r := range results {
			r := r
			cr := mapper.MapResults(&r)
			history[i] = map[string]any{
				"timestamp": r.Timestamp,
				"score":     cr.Score,
				"pass":      r.Summary.PassCount,
				"fail":      r.Summary.FailCount,
				"total":     r.Summary.TotalChecks,
			}
		}
		return cli.RenderJSON(map[string]any{
			"history": history,
			"scores":  scores,
		})
	case cli.FormatPlain:
		fmt.Println(cli.ScoreTrendPlain(scores))
		fmt.Println()
		for _, r := range results {
			r := r
			cr := mapper.MapResults(&r)
			fmt.Printf("  %s  Score: %.0f%%  Pass: %d  Fail: %d\n",
				r.Timestamp.Format(time.RFC3339), cr.Score, r.Summary.PassCount, r.Summary.FailCount)
		}
	default:
		fmt.Println(cli.ScoreTrend(scores))
		fmt.Println()
		for _, r := range results {
			r := r
			cr := mapper.MapResults(&r)
			fmt.Printf("  %s  Score: %.0f%%  Pass: %d  Fail: %d\n",
				r.Timestamp.Format(time.RFC3339), cr.Score, r.Summary.PassCount, r.Summary.FailCount)
		}
	}

	return nil
}

func filterByBenchmark(result *models.ScanResult, benchmark string) *models.ScanResult {
	filtered := &models.ScanResult{
		ID:        result.ID,
		Timestamp: result.Timestamp,
		Duration:  result.Duration,
	}
	for _, r := range result.Results {
		if r.Benchmark == benchmark {
			filtered.Results = append(filtered.Results, r)
		}
	}
	// Recompute summary
	for _, r := range filtered.Results {
		filtered.Summary.TotalChecks++
		switch r.Status {
		case models.StatusPass:
			filtered.Summary.PassCount++
		case models.StatusFail:
			filtered.Summary.FailCount++
		case models.StatusWarn:
			filtered.Summary.WarnCount++
		case models.StatusSkip:
			filtered.Summary.SkipCount++
		}
	}
	return filtered
}
