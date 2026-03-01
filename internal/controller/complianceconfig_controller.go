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

	compliancev1alpha1 "github.com/kubeshield/operator/api/v1alpha1"
	"github.com/kubeshield/operator/pkg/compliance"
	"github.com/kubeshield/operator/pkg/metrics"
	"github.com/kubeshield/operator/pkg/models"
	"github.com/kubeshield/operator/pkg/scanning"
	"github.com/kubeshield/operator/pkg/scanning/checks"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComplianceConfigReconciler reconciles a ComplianceConfig object.
type ComplianceConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=compliance.kubeshield.io,resources=complianceconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=compliance.kubeshield.io,resources=complianceconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=compliance.kubeshield.io,resources=complianceconfigs/finalizers,verbs=update
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

	// Requeue based on scanning interval
	interval := 5 * time.Minute
	if config.Spec.Scanning.Interval != "" {
		if parsed, err := time.ParseDuration(config.Spec.Scanning.Interval); err == nil {
			interval = parsed
		}
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
