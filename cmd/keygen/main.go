package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Varax license key generation tool (internal use only)",
	}

	rootCmd.AddCommand(newGenerateKeypairCmd())
	rootCmd.AddCommand(newSignCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newGenerateKeypairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate-keypair",
		Short: "Generate a new Ed25519 keypair for license signing",
		RunE:  runGenerateKeypair,
	}
}

func runGenerateKeypair(cmd *cobra.Command, args []string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	if err := os.WriteFile("private.key", priv, 0600); err != nil {
		return fmt.Errorf("failed to write private.key: %w", err)
	}

	if err := os.WriteFile("public.key", pub, 0600); err != nil {
		return fmt.Errorf("failed to write public.key: %w", err)
	}

	fmt.Println("Keypair generated: private.key, public.key")
	fmt.Println()
	fmt.Println("Copy this into pkg/license/pubkey.go:")
	fmt.Println()
	fmt.Printf("var publicKey = ed25519.PublicKey{")
	for i, b := range pub {
		if i > 0 {
			fmt.Print(", ")
		}
		if i%12 == 0 {
			fmt.Print("\n\t")
		}
		fmt.Printf("0x%02x", b)
	}
	fmt.Println(",\n}")

	return nil
}

var (
	signOrg        string
	signPlan       string
	signFeatures   string
	signDuration   string
	signPrivateKey string
)

func newSignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a new license key",
		RunE:  runSign,
	}
	cmd.Flags().StringVar(&signOrg, "org", "", "organization name (required)")
	cmd.Flags().StringVar(&signPlan, "plan", "pro-annual", "license plan")
	cmd.Flags().StringVar(&signFeatures, "features", "reports,evidence,remediation,scheduled-reports", "comma-separated feature list")
	cmd.Flags().StringVar(&signDuration, "duration", "365d", "license duration (e.g. 30d, 365d)")
	cmd.Flags().StringVar(&signPrivateKey, "private-key", "private.key", "path to private key file")
	_ = cmd.MarkFlagRequired("org")
	return cmd
}

func runSign(cmd *cobra.Command, args []string) error {
	privBytes, err := os.ReadFile(filepath.Clean(signPrivateKey))
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size: got %d, want %d", len(privBytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(privBytes)

	durationStr := strings.TrimSuffix(signDuration, "d")
	days := 0
	if _, err := fmt.Sscanf(durationStr, "%d", &days); err != nil || days <= 0 {
		return fmt.Errorf("invalid duration %q: must be like 30d or 365d", signDuration)
	}

	now := time.Now().UTC().Truncate(time.Second)
	payload := map[string]interface{}{
		"org":      signOrg,
		"plan":     signPlan,
		"issued":   now,
		"expires":  now.Add(time.Duration(days) * 24 * time.Hour),
		"features": strings.Split(signFeatures, ","),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := ed25519.Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	licenseKey := payloadB64 + "." + sigB64
	fmt.Println(licenseKey)
	return nil
}
