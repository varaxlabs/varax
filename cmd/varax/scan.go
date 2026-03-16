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
	"github.com/varax/operator/pkg/license"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	"github.com/varax/operator/pkg/remediation/remediators"
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
	scanRemediate   bool
	scanDryRun      bool
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a one-shot compliance scan against the cluster",
		RunE:  runScan,
	}
	cmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "scan timeout (e.g. 5m, 30s)")
	cmd.Flags().StringVar(&benchmark, "benchmark", "", "filter by benchmark (CIS, NSA-CISA, PSS, RBAC, WorkloadHygiene, SupplyChain, NamespaceGov, APIHygiene, IngressHardening, or all)")
	cmd.Flags().BoolVar(&collectEvidence, "evidence", false, "collect evidence bundle for auditors")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "disable animated TUI even in terminal mode")
	cmd.Flags().BoolVar(&scanRemediate, "remediate", false, "auto-remediate failed checks (Pro)")
	cmd.Flags().BoolVar(&scanDryRun, "dry-run", true, "validate remediation without applying changes")
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
	checks.RegisterWorkloadHygiene(registry)
	checks.RegisterSupplyChain(registry)
	checks.RegisterIngressHardening(registry)
	checks.RegisterNamespaceGov(registry)
	checks.RegisterAPIHygiene(registry)

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
		defer func() { _ = store.Close() }()
		if saveErr := store.SaveScanResult(scanResult); saveErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save scan result: %v\n", saveErr)
		}
		// Auto-prune records older than 90 days
		if pruned, pruneErr := store.PruneOlderThan(90 * 24 * time.Hour); pruneErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: auto-prune failed: %v\n", pruneErr)
		} else if pruned > 0 {
			fmt.Fprintf(os.Stderr, "Auto-pruned %d old record(s).\n", pruned)
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

	// Auto-remediation
	var remReport *remediation.RemediationReport
	if scanRemediate {
		if remErr := requireProFeature(license.FeatureRemediation); remErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", remErr)
		} else {
			reg := remediation.NewRemediatorRegistry()
			remediators.RegisterAll(reg)
			engine := remediation.NewEngine(reg, client, scanDryRun)

			plan, planErr := engine.PlanFromScanResult(ctx, scanResult)
			if planErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: remediation planning failed: %v\n", planErr)
			} else if len(plan.Actions) > 0 {
				var progressCb remediation.ProgressFunc
				if format == cli.FormatStyled {
					progressCb = func(completed, total int, action remediation.RemediationAction) {
						fmt.Fprintf(os.Stderr, "\r  Remediating [%d/%d] %s %s/%s",
							completed, total, action.CheckID, action.TargetKind, action.TargetName)
						if completed == total {
							fmt.Fprintln(os.Stderr)
						}
					}
				}

				var execErr error
				remReport, execErr = engine.Execute(ctx, plan, progressCb)
				if execErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: remediation failed: %v\n", execErr)
				} else if store != nil {
					if saveErr := store.SaveRemediationReport(remReport); saveErr != nil {
						fmt.Fprintf(os.Stderr, "Warning: could not save remediation report: %v\n", saveErr)
					}
				}
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
		if remReport != nil {
			output["remediation"] = remReport
		}
		return cli.RenderJSON(output)
	case cli.FormatPlain:
		fmt.Println(cli.SummaryBoxPlain(complianceResult, scanResult))
		fmt.Println(cli.ControlTablePlain(complianceResult.ControlResults))
		if evidenceBundle != nil {
			fmt.Printf("\nEvidence: collected %d items at %s\n", len(evidenceBundle.Items), evidenceBundle.CollectedAt.Format(time.RFC3339))
		}
		if remReport != nil {
			fmt.Println(cli.RemediationBoxPlain(remReport))
		}
	default:
		fmt.Println(cli.SummaryBox(complianceResult, scanResult))
		fmt.Println(cli.ControlTable(complianceResult.ControlResults))
		if evidenceBundle != nil {
			fmt.Printf("\n  Evidence: collected %d items at %s\n", len(evidenceBundle.Items), evidenceBundle.CollectedAt.Format(time.RFC3339))
		}
		if remReport != nil {
			fmt.Println(cli.RemediationBox(remReport))
		}
	}

	return nil
}
