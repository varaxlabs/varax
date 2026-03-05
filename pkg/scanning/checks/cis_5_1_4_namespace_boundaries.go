package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type NamespaceBoundariesCheck struct{}

func (c *NamespaceBoundariesCheck) ID() string      { return "CIS-5.1.4" }
func (c *NamespaceBoundariesCheck) Name() string    { return "Ensure namespace administrative boundaries" }
func (c *NamespaceBoundariesCheck) Description() string { return "Verify that at least 2 non-system namespaces exist for workload separation" }
func (c *NamespaceBoundariesCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *NamespaceBoundariesCheck) Benchmark() string         { return "CIS" }
func (c *NamespaceBoundariesCheck) Section() string            { return "5.1.4" }

func (c *NamespaceBoundariesCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	namespaces, err := scanning.ListNamespaces(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list namespaces"
		return result
	}

	nonSystemCount := 0
	for _, ns := range namespaces {
		if !isSystemNamespace(ns.Name) && ns.Name != "default" {
			nonSystemCount++
		}
	}

	if nonSystemCount >= 2 {
		result.Status = models.StatusPass
		result.Message = fmt.Sprintf("Found %d non-system namespaces for workload separation", nonSystemCount)
	} else {
		result.Status = models.StatusWarn
		result.Message = "Fewer than 2 non-system namespaces; consider using namespace boundaries"
	}

	return result
}

var _ scanning.Check = &NamespaceBoundariesCheck{}
