package selfhosted

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	auditPolicyConfigMap = "varax-audit-policy"
	auditPolicyNamespace = "kube-system"
	auditPolicyKey       = "audit-policy.yaml"
)

// auditPolicyYAML is a comprehensive audit policy following CIS Benchmark recommendations.
var auditPolicyYAML = `apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Don't log requests to the following API endpoints
  - level: None
    nonResourceURLs:
      - "/healthz*"
      - "/version"
      - "/readyz"
      - "/livez"
  # Don't log kube-system service account token fetches
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
      - group: ""
        resources: ["endpoints", "services", "services/status"]
  # Log auth failures at Metadata level
  - level: Metadata
    omitStages:
      - "RequestReceived"
    resources:
      - group: "authentication.k8s.io"
  # Log changes to key resources at RequestResponse level
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps", "serviceaccounts"]
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["create", "update", "patch", "delete"]
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods", "pods/exec", "pods/portforward", "pods/attach"]
    verbs: ["create", "update", "patch", "delete"]
  # Log everything else at Metadata level
  - level: Metadata
    omitStages:
      - "RequestReceived"
`

// SelfHostedProvider implements AuditLogProvider for self-hosted clusters
// by creating a ConfigMap with a recommended audit policy.
type SelfHostedProvider struct {
	client kubernetes.Interface
}

// NewSelfHostedProvider creates a new self-hosted audit log provider.
func NewSelfHostedProvider(client kubernetes.Interface) *SelfHostedProvider {
	return &SelfHostedProvider{client: client}
}

// IsAuditLoggingEnabled checks if the varax audit policy ConfigMap exists.
func (p *SelfHostedProvider) IsAuditLoggingEnabled(ctx context.Context) (bool, error) {
	_, err := p.client.CoreV1().ConfigMaps(auditPolicyNamespace).Get(ctx, auditPolicyConfigMap, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check audit policy ConfigMap: %w", err)
	}
	return true, nil
}

// EnableAuditLogging creates a ConfigMap with a recommended audit policy.
// For self-hosted clusters, the admin must still configure the API server to use this policy.
func (p *SelfHostedProvider) EnableAuditLogging(ctx context.Context) error {
	exists, err := p.IsAuditLoggingEnabled(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      auditPolicyConfigMap,
			Namespace: auditPolicyNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "varax",
				"app.kubernetes.io/component":  "audit-policy",
			},
		},
		Data: map[string]string{
			auditPolicyKey: auditPolicyYAML,
		},
	}

	_, err = p.client.CoreV1().ConfigMaps(auditPolicyNamespace).Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create audit policy ConfigMap: %w", err)
	}

	return nil
}
