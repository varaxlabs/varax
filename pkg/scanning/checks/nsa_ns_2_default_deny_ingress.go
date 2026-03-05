package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/kubernetes"
)

type NSADefaultDenyIngressCheck struct{}

func (c *NSADefaultDenyIngressCheck) ID() string      { return "NSA-NS-2" }
func (c *NSADefaultDenyIngressCheck) Name() string    { return "Default deny ingress NetworkPolicy" }
func (c *NSADefaultDenyIngressCheck) Description() string { return "Ensure default-deny ingress NetworkPolicy exists per namespace" }
func (c *NSADefaultDenyIngressCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *NSADefaultDenyIngressCheck) Benchmark() string         { return "NSA-CISA" }
func (c *NSADefaultDenyIngressCheck) Section() string            { return "NS-2" }

func (c *NSADefaultDenyIngressCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			// Default deny ingress: empty PodSelector + Ingress in PolicyTypes + no ingress rules
			if isDefaultDenyIngress(pol) {
				hasDefaultDeny = true
				break
			}
		}

		if !hasDefaultDeny {
			evidence = append(evidence, models.Evidence{
				Message:  fmt.Sprintf("Namespace '%s' missing default-deny ingress NetworkPolicy", ns.Name),
				Resource: models.Resource{Kind: "Namespace", Name: ns.Name},
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All namespaces have default-deny ingress NetworkPolicy"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d namespace(s) without default-deny ingress", len(evidence))
		result.Evidence = evidence
	}
	return result
}

func isDefaultDenyIngress(pol networkingv1.NetworkPolicy) bool {
	if len(pol.Spec.PodSelector.MatchLabels) > 0 || len(pol.Spec.PodSelector.MatchExpressions) > 0 {
		return false
	}
	hasIngressType := false
	for _, pt := range pol.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeIngress {
			hasIngressType = true
		}
	}
	return hasIngressType && len(pol.Spec.Ingress) == 0
}

var _ scanning.Check = &NSADefaultDenyIngressCheck{}
