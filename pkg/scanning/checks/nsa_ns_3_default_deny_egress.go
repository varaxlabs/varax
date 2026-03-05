package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/kubernetes"
)

type NSADefaultDenyEgressCheck struct{}

func (c *NSADefaultDenyEgressCheck) ID() string      { return "NSA-NS-3" }
func (c *NSADefaultDenyEgressCheck) Name() string    { return "Default deny egress NetworkPolicy" }
func (c *NSADefaultDenyEgressCheck) Description() string { return "Ensure default-deny egress NetworkPolicy exists per namespace" }
func (c *NSADefaultDenyEgressCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *NSADefaultDenyEgressCheck) Benchmark() string         { return "NSA-CISA" }
func (c *NSADefaultDenyEgressCheck) Section() string            { return "NS-3" }

func (c *NSADefaultDenyEgressCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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

		policies, err := scanning.ListNetworkPolicies(ctx, client, ns.Name)
		if err != nil {
			continue
		}

		hasDefaultDeny := false
		for _, pol := range policies {
			if isDefaultDenyEgress(pol) {
				hasDefaultDeny = true
				break
			}
		}

		if !hasDefaultDeny {
			evidence = append(evidence, models.Evidence{
				Message:  fmt.Sprintf("Namespace '%s' missing default-deny egress NetworkPolicy", ns.Name),
				Resource: models.Resource{Kind: "Namespace", Name: ns.Name},
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All namespaces have default-deny egress NetworkPolicy"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d namespace(s) without default-deny egress", len(evidence))
		result.Evidence = evidence
	}
	return result
}

func isDefaultDenyEgress(pol networkingv1.NetworkPolicy) bool {
	if len(pol.Spec.PodSelector.MatchLabels) > 0 || len(pol.Spec.PodSelector.MatchExpressions) > 0 {
		return false
	}
	hasEgressType := false
	for _, pt := range pol.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeEgress {
			hasEgressType = true
		}
	}
	return hasEgressType && len(pol.Spec.Egress) == 0
}

var _ scanning.Check = &NSADefaultDenyEgressCheck{}
