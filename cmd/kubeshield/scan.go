package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kubeshield/operator/pkg/cli"
	"github.com/kubeshield/operator/pkg/compliance"
	"github.com/kubeshield/operator/pkg/models"
	"github.com/kubeshield/operator/pkg/scanning"
	"github.com/kubeshield/operator/pkg/scanning/checks"
	"github.com/kubeshield/operator/pkg/storage"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Run a one-shot compliance scan against the cluster",
		RunE:  runScan,
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

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
