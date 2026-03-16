package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// LimitRangeCheck verifies that non-system namespaces have LimitRanges.
type LimitRangeCheck struct{}

func (c *LimitRangeCheck) ID() string          { return "NG-002" }
func (c *LimitRangeCheck) Name() string        { return "LimitRange Presence" }
func (c *LimitRangeCheck) Description() string { return "Ensure namespaces have LimitRanges to enforce default resource constraints" }
func (c *LimitRangeCheck) Severity() models.Severity { return models.SeverityLow }
func (c *LimitRangeCheck) Benchmark() string         { return BenchmarkNamespaceGov }
func (c *LimitRangeCheck) Section() string           { return "2" }

func (c *LimitRangeCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runNamespacePresenceCheck[corev1.LimitRange, *corev1.LimitRange](
		ctx, client, c, "LimitRange", scanning.ListLimitRanges,
	)
}

var _ scanning.Check = &LimitRangeCheck{}
