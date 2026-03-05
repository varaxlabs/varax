package evidence

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type networkSnapshot struct {
	TotalPolicies       int                       `json:"totalPolicies"`
	NamespaceSummaries  []namespacePolicySummary   `json:"namespaceSummaries"`
}

type namespacePolicySummary struct {
	Namespace   string `json:"namespace"`
	PolicyCount int    `json:"policyCount"`
	HasIngress  bool   `json:"hasIngress"`
	HasEgress   bool   `json:"hasEgress"`
}

func collectNetwork(ctx context.Context, client kubernetes.Interface) ([]EvidenceItem, error) {
	now := time.Now().UTC()

	policies, err := client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	snap := networkSnapshot{TotalPolicies: len(policies.Items)}

	nsSummary := make(map[string]*namespacePolicySummary)
	for _, pol := range policies.Items {
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
