package main

import (
	"fmt"

	"github.com/kubeshield/operator/pkg/cli"
	"github.com/kubeshield/operator/pkg/compliance"
	"github.com/kubeshield/operator/pkg/storage"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the latest stored compliance scan results",
		RunE:  runStatus,
	}
}

func runStatus(cmd *cobra.Command, args []string) error {
	store, err := storage.NewBoltStore(defaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer store.Close()

	scanResult, err := store.GetLatestScanResult()
	if err != nil {
		return fmt.Errorf("failed to read latest scan: %w", err)
	}
	if scanResult == nil {
		fmt.Println("No scan results found. Run 'kubeshield scan' first.")
		return nil
	}

	mapper := compliance.NewSOC2Mapper()
	complianceResult := mapper.MapResults(scanResult)

	format := cli.ResolveFormat(outputFormat)
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
