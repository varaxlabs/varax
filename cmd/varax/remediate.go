package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/varax/operator/pkg/cli"
	"github.com/varax/operator/pkg/license"
	"github.com/varax/operator/pkg/remediation"
	"github.com/varax/operator/pkg/remediation/remediators"
	"github.com/varax/operator/pkg/storage"
)

var remediateDryRun bool

func newRemediateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Auto-remediate violations from the latest scan (Pro)",
		Long:  "Loads the latest scan result from storage and applies safe remediations. Requires a Varax Pro license.",
		RunE:  runRemediate,
	}
	cmd.Flags().BoolVar(&remediateDryRun, "dry-run", true, "validate remediation without applying changes")
	return cmd
}

func runRemediate(cmd *cobra.Command, args []string) error {
	if err := requireProFeature(license.FeatureRemediation); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := buildK8sClient()
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	store, err := storage.NewBoltStore(defaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	scanResult, err := store.GetLatestScanResult()
	if err != nil {
		return fmt.Errorf("failed to load scan result: %w", err)
	}
	if scanResult == nil {
		return fmt.Errorf("no scan results found — run 'varax scan' first")
	}

	// Build engine
	reg := remediation.NewRemediatorRegistry()
	remediators.RegisterAll(reg)
	engine := remediation.NewEngine(reg, client, remediateDryRun)

	// Plan
	plan, err := engine.PlanFromScanResult(ctx, scanResult)
	if err != nil {
		return fmt.Errorf("failed to plan remediation: %w", err)
	}

	if len(plan.Actions) == 0 {
		fmt.Println("No remediable violations found.")
		return nil
	}

	format := cli.ResolveFormat(outputFormat)

	// Progress callback
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

	// Execute
	report, err := engine.Execute(ctx, plan, progressCb)
	if err != nil {
		return fmt.Errorf("remediation failed: %w", err)
	}

	// Save report
	if saveErr := store.SaveRemediationReport(report); saveErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save remediation report: %v\n", saveErr)
	}

	// Render
	switch format {
	case cli.FormatJSON:
		return cli.RenderJSON(report)
	case cli.FormatPlain:
		fmt.Println(cli.RemediationBoxPlain(report))
	default:
		fmt.Println(cli.RemediationBox(report))
	}

	return nil
}
