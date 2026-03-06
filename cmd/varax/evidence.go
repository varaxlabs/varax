package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/reports"
	"github.com/varax/operator/pkg/storage"
)

var (
	evidenceControl string
	evidenceAll     bool
	evidenceFormat  string
	evidenceOutput  string
)

func newEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Export per-control evidence for auditors",
		RunE:  runEvidence,
	}
	cmd.Flags().StringVar(&evidenceControl, "control", "", "specific control ID (e.g. CC6.1)")
	cmd.Flags().BoolVar(&evidenceAll, "all", false, "export evidence for all controls")
	cmd.Flags().StringVar(&evidenceFormat, "format", "html", "output format (html, json)")
	cmd.Flags().StringVar(&evidenceOutput, "output", "", "output file or directory path")
	return cmd
}

func runEvidence(cmd *cobra.Command, args []string) error {
	if evidenceControl == "" && !evidenceAll {
		return fmt.Errorf("specify --control <ID> or --all")
	}
	if evidenceControl != "" && evidenceAll {
		return fmt.Errorf("specify either --control or --all, not both")
	}

	rf := reports.ReportFormat(evidenceFormat)
	if rf != reports.FormatHTML && rf != reports.FormatJSON {
		return fmt.Errorf("unsupported format: %s (use html or json)", evidenceFormat)
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

	evidenceBundle, evErr := store.GetLatestEvidenceBundle()
	if evErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read evidence: %v\n", evErr)
	}

	gen := reports.NewGenerator(Version)

	if evidenceAll {
		if evidenceOutput == "" {
			return fmt.Errorf("--output directory is required when using --all")
		}
		if err := os.MkdirAll(evidenceOutput, 0750); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		for _, cr := range complianceResult.ControlResults {
			evidenceItems := reports.FilterEvidenceForControl(evidenceBundle, cr.Control.ID)
			ext := ".html"
			if rf == reports.FormatJSON {
				ext = ".json"
			}
			outPath := filepath.Join(evidenceOutput, cr.Control.ID+ext)

			if err := gen.GenerateControlDetail(outPath, rf, cr, evidenceItems, Version); err != nil {
				return fmt.Errorf("failed to generate %s: %w", cr.Control.ID, err)
			}
		}

		fmt.Fprintf(os.Stderr, "Evidence exported to %s/\n", evidenceOutput)
		return nil
	}

	// Single control
	var found bool
	for _, cr := range complianceResult.ControlResults {
		if cr.Control.ID == evidenceControl {
			evidenceItems := reports.FilterEvidenceForControl(evidenceBundle, cr.Control.ID)
			if err := gen.GenerateControlDetail(evidenceOutput, rf, cr, evidenceItems, Version); err != nil {
				return fmt.Errorf("failed to generate control detail: %w", err)
			}
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("control %s not found in compliance results", evidenceControl)
	}

	if evidenceOutput != "" && evidenceOutput != "-" {
		fmt.Fprintf(os.Stderr, "Evidence written to %s\n", evidenceOutput)
	}

	return nil
}
