package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// WildcardRBACCheck verifies that RBAC roles do not use wildcard permissions.
type WildcardRBACCheck struct{}

func (c *WildcardRBACCheck) ID() string          { return "CIS-5.1.3" }
func (c *WildcardRBACCheck) Name() string         { return "Minimize wildcard use in Roles and ClusterRoles" }
func (c *WildcardRBACCheck) Description() string {
	return "Ensure Roles and ClusterRoles do not grant wildcard (*) permissions"
}
func (c *WildcardRBACCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *WildcardRBACCheck) Benchmark() string         { return "CIS" }
func (c *WildcardRBACCheck) Section() string            { return "5.1.3" }

func (c *WildcardRBACCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	var evidence []models.Evidence

	// Check ClusterRoles
	clusterRoles, err := scanning.ListClusterRoles(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list ClusterRoles"
		return result
	}

	for _, cr := range clusterRoles {
		// Skip system ClusterRoles
		if isSystemRole(cr.Name) {
			continue
		}
		for _, rule := range cr.Rules {
			if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) || containsWildcard(rule.APIGroups) {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("ClusterRole '%s' uses wildcard permissions", cr.Name),
					Resource: models.Resource{
						Kind: "ClusterRole",
						Name: cr.Name,
					},
					Field: "rules",
				})
				break
			}
		}
	}

	// Check Roles
	roles, err := scanning.ListRoles(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list Roles"
		return result
	}

	for _, role := range roles {
		if isSystemNamespace(role.Namespace) {
			continue
		}
		for _, rule := range role.Rules {
			if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) || containsWildcard(rule.APIGroups) {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Role '%s/%s' uses wildcard permissions", role.Namespace, role.Name),
					Resource: models.Resource{
						Kind:      "Role",
						Name:      role.Name,
						Namespace: role.Namespace,
					},
					Field: "rules",
				})
				break
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No wildcard RBAC permissions found in non-system roles"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d role(s) with wildcard permissions", len(evidence))
		result.Evidence = evidence
	}

	return result
}

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

func isSystemRole(name string) bool {
	return len(name) > 7 && name[:7] == "system:"
}

func isSystemNamespace(ns string) bool {
	return ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease"
}

// allContainers returns a new slice combining init and regular containers
// without mutating the original slices (unlike append which can corrupt the backing array).
func allContainers(pod corev1.Pod) []corev1.Container {
	containers := make([]corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	containers = append(containers, pod.Spec.InitContainers...)
	containers = append(containers, pod.Spec.Containers...)
	return containers
}
