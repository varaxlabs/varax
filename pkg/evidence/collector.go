package evidence

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// CollectAll gathers all evidence from the cluster into a bundle.
func CollectAll(ctx context.Context, client kubernetes.Interface) (*EvidenceBundle, error) {
	bundle := &EvidenceBundle{
		CollectedAt: time.Now().UTC(),
	}

	// Collect RBAC evidence
	rbacItems, err := collectRBAC(ctx, client)
	if err == nil {
		bundle.Items = append(bundle.Items, rbacItems...)
	}

	// Collect network policy evidence
	netItems, err := collectNetwork(ctx, client)
	if err == nil {
		bundle.Items = append(bundle.Items, netItems...)
	}

	// Collect audit configuration evidence
	auditItems, err := collectAudit(ctx, client)
	if err == nil {
		bundle.Items = append(bundle.Items, auditItems...)
	}

	// Collect encryption evidence
	encItems, err := collectEncryption(ctx, client)
	if err == nil {
		bundle.Items = append(bundle.Items, encItems...)
	}

	return bundle, nil
}
