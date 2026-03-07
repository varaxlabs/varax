package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/varax/operator/pkg/license"
	"github.com/varax/operator/pkg/storage"
)

func newLicenseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "license",
		Short: "Manage your Varax license",
	}
	cmd.AddCommand(newLicenseStatusCmd())
	cmd.AddCommand(newLicenseActivateCmd())
	return cmd
}

func newLicenseStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current license status",
		RunE:  runLicenseStatus,
	}
}

func newLicenseActivateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "activate <KEY>",
		Short: "Activate a license key",
		Args:  cobra.ExactArgs(1),
		RunE:  runLicenseActivate,
	}
}

func runLicenseStatus(cmd *cobra.Command, args []string) error {
	var key string

	key = os.Getenv("VARAX_LICENSE")

	if key == "" {
		store, err := storage.NewBoltStore(defaultDBPath())
		if err == nil {
			defer func() { _ = store.Close() }()
			key, _ = store.GetLicense()
		}
	}

	if key == "" {
		fmt.Println("No license activated. Running in free tier.")
		fmt.Println("Purchase at: https://varax.io/pricing")
		return nil
	}

	l, err := license.ParseAndValidate(key)
	if err != nil {
		return fmt.Errorf("stored license is invalid: %w", err)
	}

	format := resolveOutputFormat()
	if format == "json" {
		return printLicenseJSON(l)
	}

	fmt.Printf("Organization: %s\n", l.Org)
	fmt.Printf("Plan:         %s\n", l.Plan)
	fmt.Printf("Features:     %v\n", l.Features)
	fmt.Printf("Issued:       %s\n", l.Issued.Format("2006-01-02"))
	fmt.Printf("Expires:      %s\n", l.Expires.Format("2006-01-02"))
	fmt.Printf("Days left:    %d\n", l.DaysUntilExpiry())

	if l.IsInGracePeriod() {
		fmt.Println("\nWarning: License expired! You are in the 5-day grace period. Renew now to avoid interruption.")
	}

	return nil
}

func runLicenseActivate(cmd *cobra.Command, args []string) error {
	key := args[0]

	l, err := license.ParseAndValidate(key)
	if err != nil {
		return fmt.Errorf("invalid license key: %w", err)
	}

	store, err := storage.NewBoltStore(defaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.SaveLicense(key); err != nil {
		return fmt.Errorf("failed to save license: %w", err)
	}

	fmt.Printf("License activated for %s (%s). Expires %s.\n", l.Org, l.Plan, l.Expires.Format("2006-01-02"))
	return nil
}

func printLicenseJSON(l *license.License) error {
	out := map[string]interface{}{
		"org":      l.Org,
		"plan":     l.Plan,
		"features": l.Features,
		"issued":   l.Issued,
		"expires":  l.Expires,
		"daysLeft": l.DaysUntilExpiry(),
		"grace":    l.IsInGracePeriod(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func resolveOutputFormat() string {
	if outputFormat != "" {
		return outputFormat
	}
	return "styled"
}
