package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type NamespaceLimitsCheck struct{}

func (c *NamespaceLimitsCheck) ID() string      { return "CIS-5.7.1" }
func (c *NamespaceLimitsCheck) Name() string    { return "Ensure namespace resource limits are set" }
func (c *NamespaceLimitsCheck) Description() string { return "Verify non-system namespaces have LimitRange or ResourceQuota" }
func (c *NamespaceLimitsCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *NamespaceLimitsCheck) Benchmark() string         { return "CIS" }
func (c *NamespaceLimitsCheck) Section() string            { return "5.7.1" }

func (c *NamespaceLimitsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	namespaces, err := scanning.ListNamespaces(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list namespaces"
		return result
	}

	var evidence []models.Evidence
	for _, ns := range namespaces {
		if isSystemNamespace(ns.Name) || ns.Name == "default" {
			continue
		}

		hasLimits := false

		// Check LimitRange
		limitRanges, err := client.CoreV1().LimitRanges(ns.Name).List(ctx, metav1.ListOptions{Limit: 1})
		if err == nil && len(limitRanges.Items) > 0 {
			hasLimits = true
		}

		// Check ResourceQuota
		if !hasLimits {
			quotas, err := client.CoreV1().ResourceQuotas(ns.Name).List(ctx, metav1.ListOptions{Limit: 1})
			if err == nil && len(quotas.Items) > 0 {
				hasLimits = true
			}
		}

		if !hasLimits {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Namespace '%s' has no LimitRange or ResourceQuota", ns.Name),
				Resource: models.Resource{
					Kind: "Namespace",
					Name: ns.Name,
				},
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All non-system namespaces have resource limits"
	} else {
		result.Status = models.StatusWarn
		result.Message = fmt.Sprintf("Found %d namespace(s) without resource limits", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &NamespaceLimitsCheck{}
