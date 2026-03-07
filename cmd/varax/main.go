package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

var (
	kubeconfig   string
	outputFormat string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "varax",
		Short: "Varax — Kubernetes SOC2 compliance automation",
		Long:  "Varax automates SOC2 compliance checking for Kubernetes clusters using CIS benchmarks.",
	}

	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig file")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "", "output format (styled, plain, json)")

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newOperatorCmd())
	rootCmd.AddCommand(newPruneCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newEvidenceCmd())
	rootCmd.AddCommand(newLicenseCmd())
	rootCmd.AddCommand(newExploreCmd())
	rootCmd.AddCommand(newRemediateCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildK8sClient() (kubernetes.Interface, error) {
	config, err := buildRESTConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func buildRESTConfig() (*rest.Config, error) {
	// 1. Explicit flag
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	// 2. KUBECONFIG env
	if env := os.Getenv("KUBECONFIG"); env != "" {
		return clientcmd.BuildConfigFromFlags("", env)
	}

	// 3. Default ~/.kube/config
	home, err := os.UserHomeDir()
	if err == nil {
		defaultPath := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(defaultPath); err == nil {
			return clientcmd.BuildConfigFromFlags("", defaultPath)
		}
	}

	// 4. In-cluster
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("could not find kubeconfig: provide --kubeconfig flag, set KUBECONFIG env, or run in-cluster")
	}
	return config, nil
}

func clusterName() string {
	cfg, err := buildRESTConfig()
	if err != nil {
		return "unknown"
	}
	if cfg.Host != "" {
		return cfg.Host
	}
	return "unknown"
}

func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "varax.db"
	}
	dir := filepath.Join(home, ".varax")
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create %s: %v\n", dir, err)
		return "varax.db"
	}
	return filepath.Join(dir, "varax.db")
}
