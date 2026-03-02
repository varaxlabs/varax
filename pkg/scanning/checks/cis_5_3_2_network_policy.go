package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// NetworkPolicyCheck verifies that all non-system namespaces have at least one NetworkPolicy.
type NetworkPolicyCheck struct{}

func (c *NetworkPolicyCheck) ID() string          { return "CIS-5.3.2" }
func (c *NetworkPolicyCheck) Name() string         { return "Ensure NetworkPolicy is configured for each namespace" }
func (c *NetworkPolicyCheck) Description() string {
	return "Every non-system namespace should have at least one NetworkPolicy to restrict traffic"
}
func (c *NetworkPolicyCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *NetworkPolicyCheck) Benchmark() string         { return "CIS" }
func (c *NetworkPolicyCheck) Section() string            { return "5.3.2" }

func (c *NetworkPolicyCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	namespaces, err := scanning.ListNamespaces(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list Namespaces"
		return result
	}

	var evidence []models.Evidence
	for _, ns := range namespaces {
		if isSystemNamespace(ns.Name) {
			continue
		}

		policies, err := scanning.ListNetworkPolicies(ctx, client, ns.Name)
		if err != nil {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Failed to list NetworkPolicies in namespace '%s'", ns.Name),
				Resource: models.Resource{
					Kind: "Namespace",
					Name: ns.Name,
				},
			})
			continue
		}

		if len(policies) == 0 {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Namespace '%s' has no NetworkPolicy", ns.Name),
				Resource: models.Resource{
					Kind: "Namespace",
					Name: ns.Name,
				},
				Field: "networkPolicies",
				Value: "0",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All non-system namespaces have at least one NetworkPolicy"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d namespace(s) without NetworkPolicy", len(evidence))
		result.Evidence = evidence
	}

	return result
}
