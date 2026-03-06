package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/reports"
	"github.com/varax/operator/pkg/storage"
)

var (
	reportFramework string
	reportFormat    string
	reportType      string
	reportOutput    string
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate an audit-ready compliance report",
		RunE:  runReport,
	}
	cmd.Flags().StringVar(&reportFramework, "framework", "soc2", "compliance framework (soc2)")
	cmd.Flags().StringVar(&reportFormat, "format", "html", "output format (html, json)")
	cmd.Flags().StringVar(&reportType, "type", "readiness", "report type (readiness, executive)")
	cmd.Flags().StringVar(&reportOutput, "output", "", "output file path (default: stdout)")
	return cmd
}

func runReport(cmd *cobra.Command, args []string) error {
	// Validate flags
	rt := reports.ReportType(reportType)
	if rt != reports.ReportTypeReadiness && rt != reports.ReportTypeExecutive {
		return fmt.Errorf("unsupported report type: %s (use readiness or executive)", reportType)
	}
	rf := reports.ReportFormat(reportFormat)
	if rf != reports.FormatHTML && rf != reports.FormatJSON {
		return fmt.Errorf("unsupported format: %s (use html or json)", reportFormat)
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

	data := &reports.ReportData{
		GeneratedAt:      time.Now().UTC(),
		ClusterName:      "default",
		Compliance:       complianceResult,
		Scan:             scanResult,
		Evidence:         evidenceBundle,
		HistoricalScores: historicalScores,
	}

	gen := reports.NewGenerator(Version)
	req := reports.ReportRequest{
		Type:       rt,
		Format:     rf,
		OutputPath: reportOutput,
	}

	if err := gen.Generate(req, data); err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	if reportOutput != "" && reportOutput != "-" {
		fmt.Fprintf(os.Stderr, "Report written to %s\n", reportOutput)
	}

	return nil
}
