package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// ResourceQuotaCheck verifies that non-system namespaces have ResourceQuotas.
type ResourceQuotaCheck struct{}

func (c *ResourceQuotaCheck) ID() string          { return "NG-001" }
func (c *ResourceQuotaCheck) Name() string        { return "ResourceQuota Presence" }
func (c *ResourceQuotaCheck) Description() string { return "Ensure namespaces have ResourceQuotas defined for resource isolation" }
func (c *ResourceQuotaCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *ResourceQuotaCheck) Benchmark() string         { return BenchmarkNamespaceGov }
func (c *ResourceQuotaCheck) Section() string           { return "1" }

func (c *ResourceQuotaCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runNamespacePresenceCheck[corev1.ResourceQuota, *corev1.ResourceQuota](
		ctx, client, c, "ResourceQuota", scanning.ListResourceQuotas,
	)
}

var _ scanning.Check = &ResourceQuotaCheck{}
