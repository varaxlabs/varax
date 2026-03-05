package controller

import (
	"context"
	"testing"
	"time"

	"github.com/varax/operator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestCountPassingControls(t *testing.T) {
	result := &models.ComplianceResult{
		ControlResults: []models.ControlResult{
			{Status: models.ControlStatusPass},
			{Status: models.ControlStatusPass},
			{Status: models.ControlStatusFail},
			{Status: models.ControlStatusPartial},
			{Status: models.ControlStatusNotAssessed},
		},
	}

	assert.Equal(t, 2, countPassingControls(result))
}

func TestCountPassingControls_NoPassing(t *testing.T) {
	result := &models.ComplianceResult{
		ControlResults: []models.ControlResult{
			{Status: models.ControlStatusFail},
			{Status: models.ControlStatusNotAssessed},
		},
	}

	assert.Equal(t, 0, countPassingControls(result))
}

func TestCountAssessedControls(t *testing.T) {
	result := &models.ComplianceResult{
		ControlResults: []models.ControlResult{
			{Status: models.ControlStatusPass},
			{Status: models.ControlStatusFail},
			{Status: models.ControlStatusPartial},
			{Status: models.ControlStatusNotAssessed},
			{Status: models.ControlStatusNotAssessed},
		},
	}

	assert.Equal(t, 3, countAssessedControls(result))
}

func TestCountAssessedControls_AllAssessed(t *testing.T) {
	result := &models.ComplianceResult{
		ControlResults: []models.ControlResult{
			{Status: models.ControlStatusPass},
			{Status: models.ControlStatusFail},
		},
	}

	assert.Equal(t, 2, countAssessedControls(result))
}

func TestRecordMetrics_DoesNotPanic(t *testing.T) {
	complianceResult := &models.ComplianceResult{
		Framework: "SOC2",
		Score:     85.0,
		ControlResults: []models.ControlResult{
			{
				Control: models.Control{ID: "CC6.1", Name: "Access Control"},
				Status:  models.ControlStatusPass,
			},
			{
				Control:        models.Control{ID: "CC6.2", Name: "Auth"},
				Status:         models.ControlStatusFail,
				ViolationCount: 3,
			},
		},
	}
	scanResult := &models.ScanResult{
		Timestamp: time.Now(),
		Duration:  5 * time.Second,
		Results: []models.CheckResult{
			{ID: "CIS-5.1.1", Severity: models.SeverityCritical, Status: models.StatusFail, Evidence: []models.Evidence{{Message: "found"}}},
			{ID: "CIS-5.2.3", Severity: models.SeverityHigh, Status: models.StatusPass},
		},
		Summary: models.ScanSummary{TotalChecks: 2, PassCount: 1, FailCount: 1},
	}

	require.NotPanics(t, func() {
		recordMetrics(complianceResult, scanResult)
	})
}

func TestDetectEKSClusterName_FromEksctlLabel(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"alpha.eksctl.io/cluster-name": "my-cluster",
				"eks.amazonaws.com/nodegroup":  "ng-1",
			},
		},
	}
	client := fake.NewSimpleClientset(node)

	name, err := detectEKSClusterName(context.Background(), client)
	require.NoError(t, err)
	assert.Equal(t, "my-cluster", name)
}

func TestDetectEKSClusterName_FromEKSLabel(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"eks.amazonaws.com/cluster": "prod-cluster",
			},
		},
	}
	client := fake.NewSimpleClientset(node)

	name, err := detectEKSClusterName(context.Background(), client)
	require.NoError(t, err)
	assert.Equal(t, "prod-cluster", name)
}

func TestDetectEKSClusterName_NoNodes(t *testing.T) {
	client := fake.NewSimpleClientset()

	_, err := detectEKSClusterName(context.Background(), client)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no nodes found")
}

func TestDetectEKSClusterName_NoMatchingLabel(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"kubernetes.io/hostname": "node-1",
			},
		},
	}
	client := fake.NewSimpleClientset(node)

	_, err := detectEKSClusterName(context.Background(), client)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not determine EKS cluster name")
}

func TestReconcileAuditLogging_SelfHosted_Creates(t *testing.T) {
	// A node with no cloud provider labels -> SelfHosted
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-1",
			Labels: map[string]string{"kubernetes.io/hostname": "node-1"},
		},
	}
	client := fake.NewSimpleClientset(node)

	// Use a context with a logger to avoid nil pointer in reconcileAuditLogging
	ctx := context.Background()
	logger := ctrl.Log.WithName("test")
	ctx = log.IntoContext(ctx, logger)

	err := reconcileAuditLogging(ctx, client)
	require.NoError(t, err)

	// Verify the audit policy ConfigMap was created
	cm, err := client.CoreV1().ConfigMaps("kube-system").Get(ctx, "varax-audit-policy", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Contains(t, cm.Data["audit-policy.yaml"], "audit.k8s.io/v1")
}

func TestReconcileAuditLogging_SelfHosted_AlreadyExists(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-1",
			Labels: map[string]string{"kubernetes.io/hostname": "node-1"},
		},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "varax-audit-policy",
			Namespace: "kube-system",
		},
		Data: map[string]string{"audit-policy.yaml": "existing"},
	}
	client := fake.NewSimpleClientset(node, cm)

	ctx := context.Background()
	logger := ctrl.Log.WithName("test")
	ctx = log.IntoContext(ctx, logger)

	err := reconcileAuditLogging(ctx, client)
	require.NoError(t, err)
}

func TestReconcileAuditLogging_AKSProvider(t *testing.T) {
	// AKS node -> detected but returns early (credentials not wired)
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"kubernetes.azure.com/cluster": "aks-cluster",
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: "azure:///subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss/virtualMachines/0",
		},
	}
	client := fake.NewSimpleClientset(node)

	ctx := context.Background()
	logger := ctrl.Log.WithName("test")
	ctx = log.IntoContext(ctx, logger)

	err := reconcileAuditLogging(ctx, client)
	require.NoError(t, err) // Returns nil (not yet fully wired)
}

func TestReconcileAuditLogging_NoNodes(t *testing.T) {
	client := fake.NewSimpleClientset()

	ctx := context.Background()
	logger := ctrl.Log.WithName("test")
	ctx = log.IntoContext(ctx, logger)

	// No nodes -> SelfHosted fallback, then creates ConfigMap
	err := reconcileAuditLogging(ctx, client)
	require.NoError(t, err)
}

func TestReconcileAuditLogging_GKEProvider(t *testing.T) {
	// GKE node -> detected but returns early (GCP credentials not wired)
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"cloud.google.com/gke-cluster-name": "my-cluster",
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: "gce://my-project/us-central1-a/gke-cluster-default-pool-abc-wxyz",
		},
	}
	client := fake.NewSimpleClientset(node)

	ctx := context.Background()
	logger := ctrl.Log.WithName("test")
	ctx = log.IntoContext(ctx, logger)

	err := reconcileAuditLogging(ctx, client)
	require.NoError(t, err) // Returns nil (not yet fully wired)
}

func TestReconcileAuditLogging_EKSProvider(t *testing.T) {
	// EKS node -> detected, attempts to create real AWS provider which fails without credentials
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"eks.amazonaws.com/cluster": "my-eks-cluster",
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: "aws:///us-east-1a/i-1234567890abcdef0",
		},
	}
	client := fake.NewSimpleClientset(node)

	ctx := context.Background()
	logger := ctrl.Log.WithName("test")
	ctx = log.IntoContext(ctx, logger)

	err := reconcileAuditLogging(ctx, client)
	assert.Error(t, err) // EKS provider creation fails without real AWS credentials
}
