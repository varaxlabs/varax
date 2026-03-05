package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsfilters "sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	compliancev1alpha1 "github.com/varax/operator/api/v1alpha1"
	"github.com/varax/operator/internal/controller"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(compliancev1alpha1.AddToScheme(scheme))
}

func newOperatorCmd() *cobra.Command {
	var metricsAddr string
	var probeAddr string
	var secureMetrics bool
	var devMode bool

	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Start the Varax controller-runtime operator",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOperator(metricsAddr, probeAddr, secureMetrics, devMode)
		},
	}

	cmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8443", "The address the metric endpoint binds to")
	cmd.Flags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to")
	cmd.Flags().BoolVar(&secureMetrics, "metrics-secure", true, "Serve metrics over HTTPS with authn/authz")
	cmd.Flags().BoolVar(&devMode, "dev-mode", false, "Enable development-mode logging (human-readable, debug level)")

	return cmd
}

func runOperator(metricsAddr, probeAddr string, secureMetrics, devMode bool) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(devMode)))
	log := ctrl.Log.WithName("setup")

	config, err := buildRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build REST config: %w", err)
	}

	metricsOpts := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
	}
	if secureMetrics {
		metricsOpts.FilterProvider = metricsfilters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:                scheme,
		Metrics:               metricsOpts,
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	if err := (&controller.ComplianceConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create controller: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	log.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "problem running manager: %v\n", err)
		return err
	}

	return nil
}
