package evidence

import (
	"context"
	"errors"
	"time"

	"k8s.io/client-go/kubernetes"
)

// CollectAll gathers all evidence from the cluster into a bundle.
// Individual collection failures are non-fatal; all errors are joined and returned.
func CollectAll(ctx context.Context, client kubernetes.Interface) (*EvidenceBundle, error) {
	bundle := &EvidenceBundle{
		CollectedAt: time.Now().UTC(),
	}

	var errs []error

	rbacItems, err := collectRBAC(ctx, client)
	if err != nil {
		errs = append(errs, err)
	} else {
		bundle.Items = append(bundle.Items, rbacItems...)
	}

	netItems, err := collectNetwork(ctx, client)
	if err != nil {
		errs = append(errs, err)
	} else {
		bundle.Items = append(bundle.Items, netItems...)
	}

	auditItems, err := collectAudit(ctx, client)
	if err != nil {
		errs = append(errs, err)
	} else {
		bundle.Items = append(bundle.Items, auditItems...)
	}

	encItems, err := collectEncryption(ctx, client)
	if err != nil {
		errs = append(errs, err)
	} else {
		bundle.Items = append(bundle.Items, encItems...)
	}

	return bundle, errors.Join(errs...)
}
