package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/license"
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
	switch {
	case evidenceControl == "" && !evidenceAll:
		return fmt.Errorf("must specify either --control or --all")
	case evidenceControl != "" && evidenceAll:
		return fmt.Errorf("cannot specify both --control and --all")
	}

	if err := requireProFeature(license.FeatureEvidence); err != nil {
		return err
	}

	rf, err := reports.ParseReportFormat(evidenceFormat)
	if err != nil {
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

		ext := ".html"
		if rf == reports.FormatJSON {
			ext = ".json"
		}

		for _, cr := range complianceResult.ControlResults {
			evidenceItems := reports.FilterEvidenceForControl(evidenceBundle, cr.Control.ID)
			outPath := filepath.Join(evidenceOutput, filepath.Base(cr.Control.ID)+ext)

			if err := gen.GenerateControlDetail(outPath, rf, cr, evidenceItems); err != nil {
				return fmt.Errorf("failed to generate %s: %w", cr.Control.ID, err)
			}
		}

		fmt.Fprintf(os.Stderr, "Evidence exported to %s/\n", evidenceOutput)
		return nil
	}

	// Single control
	for _, cr := range complianceResult.ControlResults {
		if cr.Control.ID != evidenceControl {
			continue
		}
		evidenceItems := reports.FilterEvidenceForControl(evidenceBundle, cr.Control.ID)
		if err := gen.GenerateControlDetail(evidenceOutput, rf, cr, evidenceItems); err != nil {
			return fmt.Errorf("failed to generate control detail: %w", err)
		}
		if evidenceOutput != "" && evidenceOutput != "-" {
			fmt.Fprintf(os.Stderr, "Evidence written to %s\n", evidenceOutput)
		}
		return nil
	}

	return fmt.Errorf("control %s not found in compliance results", evidenceControl)
}
