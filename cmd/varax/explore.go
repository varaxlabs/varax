package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/varax/operator/pkg/cli/tui/explore"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/license"
	"github.com/varax/operator/pkg/storage"
)

func newExploreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explore",
		Short: "Interactively browse compliance results",
		Long:  "Launch a full-screen TUI to explore SOC2 controls, check results, evidence, and remediation guidance.",
		RunE:  runExplore,
	}
}

func runExplore(cmd *cobra.Command, args []string) error {
	if err := requireProFeature(license.FeatureExplore); err != nil {
		return err
	}

	store, err := storage.NewBoltStore(defaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	scanResult, err := store.GetLatestScanResult()
	if err != nil {
		return fmt.Errorf("failed to read latest scan: %w", err)
	}
	if scanResult == nil {
		return fmt.Errorf("no scan results found — run 'varax scan' first")
	}

	mapper := compliance.NewSOC2Mapper()
	complianceResult := mapper.MapResults(scanResult)

	// Evidence (optional)
	evidenceBundle, evErr := store.GetLatestEvidenceBundle()
	if evErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read evidence: %v\n", evErr)
	}

	// Historical scores
	var historicalScores []float64
	results, listErr := store.ListScanResults(20)
	if listErr == nil && len(results) > 0 {
		historicalScores = make([]float64, len(results))
		for i, r := range results {
			r := r
			cr := mapper.MapResults(&r)
			historicalScores[len(results)-1-i] = cr.Score
		}
	}

	data := explore.Data{
		Compliance:       complianceResult,
		Scan:             scanResult,
		Evidence:         evidenceBundle,
		HistoricalScores: historicalScores,
	}

	return explore.Run(data)
}
