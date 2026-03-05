package evidence

import (
	"context"
	"fmt"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type networkSnapshot struct {
	TotalPolicies      int                      `json:"totalPolicies"`
	NamespaceSummaries []namespacePolicySummary  `json:"namespaceSummaries"`
}

type namespacePolicySummary struct {
	Namespace   string `json:"namespace"`
	PolicyCount int    `json:"policyCount"`
	HasIngress  bool   `json:"hasIngress"`
	HasEgress   bool   `json:"hasEgress"`
}

func collectNetwork(ctx context.Context, client kubernetes.Interface) ([]EvidenceItem, error) {
	now := time.Now().UTC()

	// Paginated fetch of all NetworkPolicies
	var allPolicies []networkingv1.NetworkPolicy
	opts := metav1.ListOptions{Limit: evidencePageSize}
	for {
		policies, err := client.NetworkingV1().NetworkPolicies("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		allPolicies = append(allPolicies, policies.Items...)
		if policies.Continue == "" {
			break
		}
		opts.Continue = policies.Continue
	}

	snap := networkSnapshot{TotalPolicies: len(allPolicies)}

	nsSummary := make(map[string]*namespacePolicySummary)
	for _, pol := range allPolicies {
		s, ok := nsSummary[pol.Namespace]
		if !ok {
			s = &namespacePolicySummary{Namespace: pol.Namespace}
			nsSummary[pol.Namespace] = s
		}
		s.PolicyCount++
		for _, pt := range pol.Spec.PolicyTypes {
			if pt == "Ingress" {
				s.HasIngress = true
			}
			if pt == "Egress" {
				s.HasEgress = true
			}
		}
	}

	for _, s := range nsSummary {
		snap.NamespaceSummaries = append(snap.NamespaceSummaries, *s)
	}

	return []EvidenceItem{{
		Category:    "Network",
		Description: fmt.Sprintf("NetworkPolicy snapshot: %d policies across %d namespaces", snap.TotalPolicies, len(nsSummary)),
		Data:        snap,
		Timestamp:   now,
	}}, nil
}
