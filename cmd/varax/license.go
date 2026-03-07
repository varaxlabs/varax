package main

import (
	"encoding/json"
	"errors"
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
	cmd.AddCommand(newLicenseRefreshCmd())
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

func newLicenseRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Refresh license key from Varax licensing server",
		RunE:  runLicenseRefresh,
	}
}

func runLicenseRefresh(cmd *cobra.Command, args []string) error {
	store, err := storage.NewBoltStore(defaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	key := os.Getenv("VARAX_LICENSE")
	if key == "" {
		key, _ = store.GetLicense()
	}
	if key == "" {
		return fmt.Errorf("no license to refresh. Activate one first with: varax license activate <KEY>")
	}

	client := license.NewClient(os.Getenv("VARAX_API_URL"), nil)
	newKey, err := client.RefreshLicense(cmd.Context(), key)
	if err != nil {
		switch {
		case errors.Is(err, license.ErrSubscriptionInactive):
			return fmt.Errorf("subscription is no longer active. Renew at: https://varax.io/pricing")
		case errors.Is(err, license.ErrLicenseNotFound):
			return fmt.Errorf("license not recognized by server. Contact support at: https://varax.io/support")
		case errors.Is(err, license.ErrRateLimited):
			return fmt.Errorf("rate limited — please try again later")
		case errors.Is(err, license.ErrServerError):
			return fmt.Errorf("licensing server error — please try again later")
		default:
			return fmt.Errorf("failed to refresh license: %w", err)
		}
	}

	l, err := license.ParseAndValidate(newKey)
	if err != nil {
		return fmt.Errorf("server returned invalid license key: %w", err)
	}

	if err := store.SaveLicense(newKey); err != nil {
		return fmt.Errorf("failed to save refreshed license: %w", err)
	}

	format := resolveOutputFormat()
	if format == "json" {
		return printLicenseJSON(l)
	}

	fmt.Printf("License refreshed successfully.\n")
	fmt.Printf("Organization: %s\n", l.Org)
	fmt.Printf("Plan:         %s\n", l.Plan)
	fmt.Printf("Expires:      %s\n", l.Expires.Format("2006-01-02"))
	fmt.Printf("Days left:    %d\n", l.DaysUntilExpiry())
	return nil
}

func resolveOutputFormat() string {
	if outputFormat != "" {
		return outputFormat
	}
	return "styled"
}
