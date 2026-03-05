package controller

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	compliancev1alpha1 "github.com/varax/operator/api/v1alpha1"
	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/metrics"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/providers"
	awsprovider "github.com/varax/operator/pkg/providers/aws"
	azureprovider "github.com/varax/operator/pkg/providers/azure"
	gkeprovider "github.com/varax/operator/pkg/providers/gke"
	"github.com/varax/operator/pkg/providers/selfhosted"
	"github.com/varax/operator/pkg/scanning"
	"github.com/varax/operator/pkg/scanning/checks"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComplianceConfigReconciler reconciles a ComplianceConfig object.
type ComplianceConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=compliance.varax.io,resources=complianceconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=compliance.varax.io,resources=complianceconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=compliance.varax.io,resources=complianceconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods;namespaces;serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings;roles;rolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch

func (r *ComplianceConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var config compliancev1alpha1.ComplianceConfig
	if err := r.Get(ctx, req.NamespacedName, &config); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling ComplianceConfig", "name", config.Name)

	// Update phase to Scanning
	config.Status.Phase = compliancev1alpha1.PhaseScanning
	if err := r.Status().Update(ctx, &config); err != nil {
		logger.Error(err, "failed to update status to Scanning")
		return ctrl.Result{}, err
	}

	// Build a plain kubernetes clientset from the manager's rest config
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get rest config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create clientset: %w", err)
	}

	// Auto-enable audit logging if configured
	if config.Spec.AuditLogging.Enabled {
		if err := reconcileAuditLogging(ctx, clientset); err != nil {
			logger.Error(err, "failed to enable audit logging (non-fatal, continuing scan)")
		}
	}

	// Run scan
	registry := scanning.NewRegistry()
	checks.RegisterAll(registry)
	runner := scanning.NewScanRunner(registry, clientset)

	scanResult, err := runner.RunAll(ctx, nil)
	if err != nil {
		config.Status.Phase = compliancev1alpha1.PhaseError
		if updateErr := r.Status().Update(ctx, &config); updateErr != nil {
			logger.Error(updateErr, "failed to update status to Error")
		}
		return ctrl.Result{}, fmt.Errorf("scan failed: %w", err)
	}

	// Map to compliance
	mapper := compliance.NewSOC2Mapper()
	complianceResult := mapper.MapResults(scanResult)

	// Update CRD status
	now := metav1.Now()
	config.Status.LastScanTime = &now
	config.Status.ComplianceScore = int(complianceResult.Score)
	config.Status.ViolationCount = scanResult.Summary.FailCount
	config.Status.FrameworkStatus = []compliancev1alpha1.FrameworkStatus{
		{
			Name:            complianceResult.Framework,
			Score:           int(complianceResult.Score),
			PassingControls: countPassingControls(complianceResult),
			TotalControls:   countAssessedControls(complianceResult),
		},
	}

	if scanResult.Summary.FailCount > 0 {
		config.Status.Phase = compliancev1alpha1.PhaseViolations
	} else {
		config.Status.Phase = compliancev1alpha1.PhaseCompliant
	}

	if err := r.Status().Update(ctx, &config); err != nil {
		logger.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	// Record Prometheus metrics
	recordMetrics(complianceResult, scanResult)

	// Requeue based on scanning interval (minimum 1 minute to prevent DoS)
	interval := 5 * time.Minute
	if config.Spec.Scanning.Interval != "" {
		if parsed, err := time.ParseDuration(config.Spec.Scanning.Interval); err == nil {
			interval = parsed
		}
	}
	if interval < time.Minute {
		interval = time.Minute
	}

	logger.Info("Scan complete", "score", complianceResult.Score, "requeueAfter", interval)
	return ctrl.Result{RequeueAfter: interval}, nil
}

func (r *ComplianceConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&compliancev1alpha1.ComplianceConfig{}).
		Complete(r)
}

func countPassingControls(result *models.ComplianceResult) int {
	count := 0
	for _, cr := range result.ControlResults {
		if cr.Status == models.ControlStatusPass {
			count++
		}
	}
	return count
}

func countAssessedControls(result *models.ComplianceResult) int {
	count := 0
	for _, cr := range result.ControlResults {
		if cr.Status != models.ControlStatusNotAssessed {
			count++
		}
	}
	return count
}

func reconcileAuditLogging(ctx context.Context, clientset kubernetes.Interface) error {
	logger := log.FromContext(ctx)

	providerType, err := providers.DetectProvider(ctx, clientset)
	if err != nil {
		return fmt.Errorf("failed to detect cloud provider: %w", err)
	}

	var auditProvider providers.AuditLogProvider
	clusterName := "unknown"

	switch providerType {
	case providers.ProviderEKS:
		// EKS cluster name is available via the node's providerID or labels
		name, err := detectEKSClusterName(ctx, clientset)
		if err != nil {
			return fmt.Errorf("failed to detect EKS cluster name: %w", err)
		}
		clusterName = name
		eksProvider, err := awsprovider.NewEKSProvider(ctx, clusterName)
		if err != nil {
			return fmt.Errorf("failed to create EKS provider: %w", err)
		}
		auditProvider = eksProvider
	case providers.ProviderAKS:
		info, err := detectAKSClusterInfo(ctx, clientset)
		if err != nil {
			return fmt.Errorf("failed to detect AKS cluster info: %w", err)
		}
		clusterName = info.ClusterName
		auditProvider = azureprovider.NewAKSProviderWithClient(nil, info.SubscriptionID, info.ResourceGroup, info.ClusterName)
		// Note: real Azure client requires azidentity credentials; using nil client here
		// will fail at runtime. Production use requires NewAKSProvider with proper Azure SDK setup.
		logger.Info("AKS audit log provider not yet fully wired (Azure SDK credentials required)", "cluster", clusterName)
		return nil
	case providers.ProviderGKE:
		info, err := detectGKEClusterInfo(ctx, clientset)
		if err != nil {
			return fmt.Errorf("failed to detect GKE cluster info: %w", err)
		}
		clusterName = info.ClusterName
		_ = gkeprovider.NewGKEProviderWithClient(nil, info.Project, info.Location, info.ClusterName)
		// Note: real GKE client requires GCP credentials; not yet wired.
		logger.Info("GKE audit log provider not yet fully wired (GCP credentials required)", "cluster", clusterName)
		return nil
	case providers.ProviderSelfHosted:
		clusterName = "self-hosted"
		auditProvider = selfhosted.NewSelfHostedProvider(clientset)
	}

	enabled, err := auditProvider.IsAuditLoggingEnabled(ctx)
	if err != nil {
		return fmt.Errorf("failed to check audit logging status: %w", err)
	}

	if enabled {
		logger.Info("Audit logging already enabled", "provider", providerType, "cluster", clusterName)
		metrics.AuditLoggingEnabled.WithLabelValues(string(providerType), clusterName).Set(1)
		return nil
	}

	logger.Info("Enabling audit logging", "provider", providerType, "cluster", clusterName)
	if err := auditProvider.EnableAuditLogging(ctx); err != nil {
		metrics.AuditLoggingEnabled.WithLabelValues(string(providerType), clusterName).Set(0)
		return fmt.Errorf("failed to enable audit logging: %w", err)
	}

	metrics.AuditLoggingEnabled.WithLabelValues(string(providerType), clusterName).Set(1)
	logger.Info("Audit logging enabled successfully", "provider", providerType, "cluster", clusterName)
	return nil
}

// detectEKSClusterName extracts the EKS cluster name from node providerID.
// The providerID format is: aws:///ZONE/INSTANCE_ID but the cluster name
// is available via the eks.amazonaws.com/cluster label on EKS-managed nodes.
func detectEKSClusterName(ctx context.Context, clientset kubernetes.Interface) (string, error) {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return "", err
	}
	if len(nodes.Items) == 0 {
		return "", fmt.Errorf("no nodes found")
	}

	labels := nodes.Items[0].Labels
	if name, ok := labels["alpha.eksctl.io/cluster-name"]; ok {
		return name, nil
	}
	if name, ok := labels["eks.amazonaws.com/cluster"]; ok {
		return name, nil
	}

	// Fallback: try node name patterns or ConfigMap
	return "", fmt.Errorf("could not determine EKS cluster name from node labels; set CLUSTER_NAME env var")
}

func detectAKSClusterInfo(ctx context.Context, clientset kubernetes.Interface) (*azureprovider.AKSClusterInfo, error) {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return nil, err
	}
	return azureprovider.DetectAKSClusterInfo(nodes.Items)
}

func detectGKEClusterInfo(ctx context.Context, clientset kubernetes.Interface) (*gkeprovider.GKEClusterInfo, error) {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return nil, err
	}
	return gkeprovider.DetectGKEClusterInfo(nodes.Items)
}

func recordMetrics(complianceResult *models.ComplianceResult, scanResult *models.ScanResult) {
	metrics.ComplianceScore.WithLabelValues(complianceResult.Framework, "default").Set(complianceResult.Score)
	metrics.LastScanTimestamp.Set(float64(scanResult.Timestamp.Unix()))
	metrics.ScanDuration.Set(scanResult.Duration.Seconds())

	metrics.ChecksTotal.WithLabelValues("pass").Set(float64(scanResult.Summary.PassCount))
	metrics.ChecksTotal.WithLabelValues("fail").Set(float64(scanResult.Summary.FailCount))
	metrics.ChecksTotal.WithLabelValues("warn").Set(float64(scanResult.Summary.WarnCount))
	metrics.ChecksTotal.WithLabelValues("skip").Set(float64(scanResult.Summary.SkipCount))

	// Per-severity violation counts
	severityCounts := make(map[string]int)
	for _, r := range scanResult.Results {
		if r.Status == models.StatusFail {
			severityCounts[string(r.Severity)] += len(r.Evidence)
		}
	}
	for severity, count := range severityCounts {
		metrics.ViolationsTotal.WithLabelValues(severity, complianceResult.Framework).Set(float64(count))
	}

	for _, cr := range complianceResult.ControlResults {
		metrics.RecordControlStatus(complianceResult.Framework, cr.Control.ID, string(cr.Status))
	}
}
