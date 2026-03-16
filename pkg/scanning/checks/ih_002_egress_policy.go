package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/kubernetes"
)

// EgressPolicyCheck verifies that namespaces have egress NetworkPolicies
// restricting outbound traffic.
type EgressPolicyCheck struct{}

func (c *EgressPolicyCheck) ID() string          { return "IH-002" }
func (c *EgressPolicyCheck) Name() string        { return "Egress NetworkPolicy" }
func (c *EgressPolicyCheck) Description() string { return "Ensure namespaces have egress NetworkPolicies restricting outbound traffic" }
func (c *EgressPolicyCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *EgressPolicyCheck) Benchmark() string         { return BenchmarkIngressHardening }
func (c *EgressPolicyCheck) Section() string           { return "2" }

func (c *EgressPolicyCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	namespaces, err := scanning.ListNamespaces(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list namespaces"
		return result
	}

	policies, err := scanning.ListNetworkPolicies(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list network policies"
		return result
	}

	// Build set of namespaces that have at least one egress policy
	nsWithEgress := make(map[string]bool)
	for _, np := range policies {
		for _, pt := range np.Spec.PolicyTypes {
			if pt == networkingv1.PolicyTypeEgress {
				nsWithEgress[np.Namespace] = true
				break
			}
		}
	}

	var evidence []models.Evidence
	for _, ns := range namespaces {
		if isSystemNamespace(ns.Name) {
			continue
		}
		if !nsWithEgress[ns.Name] {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Namespace '%s' has no egress NetworkPolicy — outbound traffic is unrestricted",
					ns.Name),
				Resource: models.Resource{Kind: "Namespace", Name: ns.Name},
				Field:    "NetworkPolicy.spec.policyTypes",
				Value:    "no egress policy",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All non-system namespaces have egress NetworkPolicies"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d namespace(s) without egress NetworkPolicies", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &EgressPolicyCheck{}
