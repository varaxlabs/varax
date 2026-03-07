package remediators

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	"k8s.io/client-go/kubernetes"
)

// ownerKey is used for deduplication.
type ownerKey struct {
	Kind, Name, Namespace string
}

// resolveUniqueOwners resolves pod evidence to workload owners, deduplicating.
func resolveUniqueOwners(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) map[ownerKey]*remediation.WorkloadOwner {
	owners := make(map[ownerKey]*remediation.WorkloadOwner)
	for _, ev := range evidence {
		if ev.Resource.Kind != "Pod" {
			continue
		}
		owner, err := remediation.ResolveOwner(ctx, client, ev.Resource.Namespace, ev.Resource.Name)
		if err != nil {
			continue
		}
		key := ownerKey{Kind: owner.Kind, Name: owner.Name, Namespace: owner.Namespace}
		owners[key] = owner
	}
	return owners
}

// containerNameFromField extracts the container name from evidence field strings
// like "spec.containers[app].securityContext.allowPrivilegeEscalation".
func containerNameFromField(field string) string {
	start := strings.Index(field, "[")
	end := strings.Index(field, "]")
	if start >= 0 && end > start {
		return field[start+1 : end]
	}
	return ""
}

// containerNamesFromEvidence collects unique container names from evidence for a given pod owner.
func containerNamesFromEvidence(evidence []models.Evidence, owner *remediation.WorkloadOwner) []string {
	seen := make(map[string]bool)
	var names []string
	for _, ev := range evidence {
		name := containerNameFromField(ev.Field)
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		names = append(names, "app")
	}
	return names
}
