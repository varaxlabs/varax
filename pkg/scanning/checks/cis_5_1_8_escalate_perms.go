package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// EscalatePermsCheck verifies that RBAC roles do not grant bind, escalate, or impersonate verbs.
type EscalatePermsCheck struct{}

func (c *EscalatePermsCheck) ID() string      { return "CIS-5.1.8" }
func (c *EscalatePermsCheck) Name() string     { return "Limit use of the Bind, Impersonate and Escalate permissions" }
func (c *EscalatePermsCheck) Description() string {
	return "Ensure that roles do not grant bind, escalate, or impersonate permissions"
}
func (c *EscalatePermsCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *EscalatePermsCheck) Benchmark() string         { return "CIS" }
func (c *EscalatePermsCheck) Section() string            { return "5.1.8" }

func (c *EscalatePermsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			if hasEscalationVerbs(rule.Verbs) {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("ClusterRole '%s' grants escalation permissions", cr.Name),
					Resource: models.Resource{
						Kind: "ClusterRole",
						Name: cr.Name,
					},
					Field: "rules.verbs",
					Value: "bind/escalate/impersonate",
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
			if hasEscalationVerbs(rule.Verbs) {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Role '%s/%s' grants escalation permissions", role.Namespace, role.Name),
					Resource: models.Resource{
						Kind:      "Role",
						Name:      role.Name,
						Namespace: role.Namespace,
					},
					Field: "rules.verbs",
					Value: "bind/escalate/impersonate",
				})
				break
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No non-system roles grant bind, escalate, or impersonate permissions"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d role(s) with escalation permissions", len(evidence))
		result.Evidence = evidence
	}

	return result
}

func hasEscalationVerbs(verbs []string) bool {
	for _, v := range verbs {
		if v == "bind" || v == "escalate" || v == "impersonate" {
			return true
		}
	}
	return false
}
