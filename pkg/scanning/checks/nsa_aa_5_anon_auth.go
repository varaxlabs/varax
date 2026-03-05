package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type NSAAnonAuthCheck struct{}

func (c *NSAAnonAuthCheck) ID() string          { return "NSA-AA-5" }
func (c *NSAAnonAuthCheck) Name() string        { return "Anonymous authentication disabled" }
func (c *NSAAnonAuthCheck) Description() string { return "Ensure anonymous authentication is disabled via API server or RBAC" }
func (c *NSAAnonAuthCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *NSAAnonAuthCheck) Benchmark() string         { return "NSA-CISA" }
func (c *NSAAnonAuthCheck) Section() string            { return "AA-5" }

func (c *NSAAnonAuthCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	// Check if anonymous ClusterRoleBindings exist
	bindings, err := scanning.ListClusterRoleBindings(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list ClusterRoleBindings"
		return result
	}

	var evidence []models.Evidence
	for _, binding := range bindings {
		for _, subject := range binding.Subjects {
			if subject.Kind == "User" && subject.Name == "system:anonymous" {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("ClusterRoleBinding '%s' grants access to system:anonymous", binding.Name),
					Resource: models.Resource{Kind: "ClusterRoleBinding", Name: binding.Name},
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No RBAC bindings for anonymous users"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d binding(s) granting anonymous access", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &NSAAnonAuthCheck{}
