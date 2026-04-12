package evidence

import (
	"context"
	"fmt"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NetworkSnapshot contains a summary of NetworkPolicy resources.
type NetworkSnapshot struct {
	TotalPolicies      int                       `json:"totalPolicies"`
	NamespaceSummaries []NamespacePolicySummary   `json:"namespaceSummaries"`
}

// NamespacePolicySummary describes NetworkPolicy coverage for a single namespace.
type NamespacePolicySummary struct {
	Namespace   string `json:"namespace"`
	PolicyCount int    `json:"policyCount"`
	HasIngress  bool   `json:"hasIngress"`
	HasEgress   bool   `json:"hasEgress"`
}

// DefaultDenySnapshot summarizes default-deny NetworkPolicy status per namespace.
type DefaultDenySnapshot struct {
	TotalNamespaces       int      `json:"totalNamespaces"`
	NamespacesWithDeny    int      `json:"namespacesWithDeny"`
	NamespacesWithoutDeny []string `json:"namespacesWithoutDeny,omitempty"`
}

func collectNetwork(ctx context.Context, client kubernetes.Interface) ([]EvidenceItem, error) {
	now := time.Now().UTC()

	// Fetch all namespaces
	nsList, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	allNamespaces := make(map[string]bool, len(nsList.Items))
	for _, ns := range nsList.Items {
		allNamespaces[ns.Name] = true
	}

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

	snap := NetworkSnapshot{TotalPolicies: len(allPolicies)}
	denySnap := DefaultDenySnapshot{TotalNamespaces: len(allNamespaces)}

	nsSummary := make(map[string]*NamespacePolicySummary)
	nsHasDefaultDeny := make(map[string]bool)

	for _, pol := range allPolicies {
		s, ok := nsSummary[pol.Namespace]
		if !ok {
			s = &NamespacePolicySummary{Namespace: pol.Namespace}
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

		// Check for default-deny pattern: empty podSelector and no ingress/egress rules
		if len(pol.Spec.PodSelector.MatchLabels) == 0 &&
			len(pol.Spec.PodSelector.MatchExpressions) == 0 &&
			len(pol.Spec.Ingress) == 0 && len(pol.Spec.Egress) == 0 {
			nsHasDefaultDeny[pol.Namespace] = true
		}
	}

	for _, s := range nsSummary {
		snap.NamespaceSummaries = append(snap.NamespaceSummaries, *s)
	}

	// Compute default-deny coverage
	for ns := range allNamespaces {
		if nsHasDefaultDeny[ns] {
			denySnap.NamespacesWithDeny++
		} else {
			denySnap.NamespacesWithoutDeny = append(denySnap.NamespacesWithoutDeny, ns)
		}
	}

	items := []EvidenceItem{
		{
			Category:    "Network",
			Type:        "network-policy-coverage",
			Description: fmt.Sprintf("NetworkPolicy coverage: %d policies across %d namespaces", snap.TotalPolicies, len(nsSummary)),
			Data:        snap,
			Timestamp:   now,
			SHA256:      computeSHA256(snap),
		},
		{
			Category:    "Network",
			Type:        "default-deny-status",
			Description: fmt.Sprintf("Default-deny status: %d of %d namespaces have default-deny policies", denySnap.NamespacesWithDeny, denySnap.TotalNamespaces),
			Data:        denySnap,
			Timestamp:   now,
			SHA256:      computeSHA256(denySnap),
		},
	}

	return items, nil
}
