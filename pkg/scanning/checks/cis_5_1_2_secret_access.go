package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// SecretAccessCheck verifies that RBAC roles do not grant broad access to secrets.
type SecretAccessCheck struct{}

func (c *SecretAccessCheck) ID() string      { return "CIS-5.1.2" }
func (c *SecretAccessCheck) Name() string     { return "Minimize access to secrets" }
func (c *SecretAccessCheck) Description() string {
	return "Ensure that Roles and ClusterRoles do not grant get/list access to secrets broadly"
}
func (c *SecretAccessCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *SecretAccessCheck) Benchmark() string         { return "CIS" }
func (c *SecretAccessCheck) Section() string            { return "5.1.2" }

func (c *SecretAccessCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	var evidence []models.Evidence

	clusterRoles, err := scanning.ListClusterRoles(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list ClusterRoles"
		return result
	}

	for _, cr := range clusterRoles {
		if isSystemRole(cr.Name) {
			continue
		}
		for _, rule := range cr.Rules {
			if containsString(rule.Resources, "secrets") && hasSecretVerbs(rule.Verbs) {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("ClusterRole '%s' grants access to secrets", cr.Name),
					Resource: models.Resource{
						Kind: "ClusterRole",
						Name: cr.Name,
					},
					Field: "rules",
					Value: "get/list on secrets",
				})
				break
			}
		}
	}

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
			if containsString(rule.Resources, "secrets") && hasSecretVerbs(rule.Verbs) {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Role '%s/%s' grants access to secrets", role.Namespace, role.Name),
					Resource: models.Resource{
						Kind:      "Role",
						Name:      role.Name,
						Namespace: role.Namespace,
					},
					Field: "rules",
					Value: "get/list on secrets",
				})
				break
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No non-system roles grant broad access to secrets"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d role(s) granting access to secrets", len(evidence))
		result.Evidence = evidence
	}

	return result
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target || item == "*" {
			return true
		}
	}
	return false
}

func hasSecretVerbs(verbs []string) bool {
	for _, v := range verbs {
		if v == "get" || v == "list" || v == "*" {
			return true
		}
	}
	return false
}
