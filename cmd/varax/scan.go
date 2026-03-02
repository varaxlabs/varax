package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/varax/operator/pkg/cli"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"github.com/varax/operator/pkg/scanning/checks"
	"github.com/varax/operator/pkg/storage"
	"github.com/spf13/cobra"
)

var scanTimeout time.Duration

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a one-shot compliance scan against the cluster",
		RunE:  runScan,
	}
	cmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "scan timeout (e.g. 5m, 30s)")
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

	// Run scan
	format := cli.ResolveFormat(outputFormat)
	runner := scanning.NewScanRunner(registry, client)

	var progressCb scanning.ProgressCallback
	if format == cli.FormatStyled {
		progressCb = func(completed, total int, current models.CheckResult) {
			fmt.Fprintf(os.Stderr, "\r  Scanning [%d/%d] %s", completed, total, current.Name)
			if completed == total {
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	scanResult, err := runner.RunAll(ctx, progressCb)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Map to compliance results
	mapper := compliance.NewSOC2Mapper()
	complianceResult := mapper.MapResults(scanResult)

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

	// Render output
	switch format {
	case cli.FormatJSON:
		return cli.RenderJSON(map[string]any{
			"scan":       scanResult,
			"compliance": complianceResult,
		})
	case cli.FormatPlain:
		fmt.Println(cli.SummaryBoxPlain(complianceResult, scanResult))
		fmt.Println(cli.ControlTablePlain(complianceResult.ControlResults))
	default:
		fmt.Println(cli.SummaryBox(complianceResult, scanResult))
		fmt.Println(cli.ControlTable(complianceResult.ControlResults))
	}

	return nil
}
