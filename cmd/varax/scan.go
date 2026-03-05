package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/varax/operator/pkg/cli"
	"github.com/varax/operator/pkg/cli/tui"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"github.com/varax/operator/pkg/scanning/checks"
	"github.com/varax/operator/pkg/storage"
	"github.com/spf13/cobra"
)

var (
	scanTimeout     time.Duration
	benchmark       string
	collectEvidence bool
	noTUI           bool
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a one-shot compliance scan against the cluster",
		RunE:  runScan,
	}
	cmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "scan timeout (e.g. 5m, 30s)")
	cmd.Flags().StringVar(&benchmark, "benchmark", "", "filter by benchmark (CIS, NSA-CISA, PSS, RBAC, or all)")
	cmd.Flags().BoolVar(&collectEvidence, "evidence", false, "collect evidence bundle for auditors")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "disable animated TUI even in terminal mode")
	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	client, err := buildK8sClient()
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Build registry and register all checks
	registry := scanning.NewRegistry()
	checks.RegisterAll(registry)
	checks.RegisterNSACISA(registry)
	checks.RegisterPSS(registry)
	checks.RegisterRBAC(registry)

	// Filter by benchmark if specified
	if benchmark != "" && benchmark != "all" {
		filtered := scanning.NewRegistry()
		for _, c := range registry.ByBenchmark(benchmark) {
			filtered.Register(c)
		}
		registry = filtered
	}

	// Run scan
	format := cli.ResolveFormat(outputFormat)
	runner := scanning.NewScanRunner(registry, client)
	mapper := compliance.NewSOC2Mapper()

	var scanResult *models.ScanResult
	var complianceResult *models.ComplianceResult

	// Use TUI for styled terminal output (unless --no-tui)
	if format == cli.FormatStyled && cli.IsTTY() && !noTUI {
		var tuiErr error
		scanResult, complianceResult, tuiErr = tui.RunScanWithTUI(ctx, runner, mapper)
		if tuiErr != nil {
			return fmt.Errorf("scan failed: %w", tuiErr)
		}
	} else {
		var progressCb scanning.ProgressCallback
		if format == cli.FormatStyled {
			progressCb = func(completed, total int, current models.CheckResult) {
				fmt.Fprintf(os.Stderr, "\r  Scanning [%d/%d] %s", completed, total, current.Name)
				if completed == total {
					fmt.Fprintln(os.Stderr)
				}
			}
		}

		var runErr error
		scanResult, runErr = runner.RunAll(ctx, progressCb)
		if runErr != nil {
			return fmt.Errorf("scan failed: %w", runErr)
		}
		complianceResult = mapper.MapResults(scanResult)
	}

	// Save to BoltDB
	store, err := storage.NewBoltStore(defaultDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not open storage: %v\n", err)
	} else {
		defer store.Close()
		if saveErr := store.SaveScanResult(scanResult); saveErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save scan result: %v\n", saveErr)
		}
	}

	// Collect evidence if requested
	var evidenceBundle *evidence.EvidenceBundle
	if collectEvidence {
		var evErr error
		evidenceBundle, evErr = evidence.CollectAll(ctx, client)
		if evErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: evidence collection failed: %v\n", evErr)
		} else if store != nil {
			if saveErr := store.SaveEvidenceBundle(evidenceBundle); saveErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not save evidence bundle: %v\n", saveErr)
			}
		}
	}

	// Render output
	switch format {
	case cli.FormatJSON:
		output := map[string]any{
			"scan":       scanResult,
			"compliance": complianceResult,
		}
		if evidenceBundle != nil {
			output["evidence"] = evidenceBundle
		}
		return cli.RenderJSON(output)
	case cli.FormatPlain:
		fmt.Println(cli.SummaryBoxPlain(complianceResult, scanResult))
		fmt.Println(cli.ControlTablePlain(complianceResult.ControlResults))
		if evidenceBundle != nil {
			fmt.Printf("\nEvidence: collected %d items at %s\n", len(evidenceBundle.Items), evidenceBundle.CollectedAt.Format(time.RFC3339))
		}
	default:
		fmt.Println(cli.SummaryBox(complianceResult, scanResult))
		fmt.Println(cli.ControlTable(complianceResult.ControlResults))
		if evidenceBundle != nil {
			fmt.Printf("\n  Evidence: collected %d items at %s\n", len(evidenceBundle.Items), evidenceBundle.CollectedAt.Format(time.RFC3339))
		}
	}

	return nil
}
