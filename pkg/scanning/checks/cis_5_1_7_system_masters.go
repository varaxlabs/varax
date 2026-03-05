package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type SystemMastersCheck struct{}

func (c *SystemMastersCheck) ID() string      { return "CIS-5.1.7" }
func (c *SystemMastersCheck) Name() string    { return "Avoid use of system:masters group" }
func (c *SystemMastersCheck) Description() string { return "Ensure cluster role bindings do not bind to system:masters group" }
func (c *SystemMastersCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *SystemMastersCheck) Benchmark() string         { return "CIS" }
func (c *SystemMastersCheck) Section() string            { return "5.1.7" }

func (c *SystemMastersCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	bindings, err := scanning.ListClusterRoleBindings(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list ClusterRoleBindings"
		return result
	}

	var evidence []models.Evidence
	for _, binding := range bindings {
		if isSystemRole(binding.Name) {
			continue
		}
		for _, subject := range binding.Subjects {
			if subject.Kind == "Group" && subject.Name == "system:masters" {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("ClusterRoleBinding '%s' binds to system:masters group", binding.Name),
					Resource: models.Resource{
						Kind: "ClusterRoleBinding",
						Name: binding.Name,
					},
					Field: "subjects",
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No non-system bindings to system:masters group"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d binding(s) to system:masters group", len(evidence))
		result.Evidence = evidence
	}

	return result
}

var _ scanning.Check = &SystemMastersCheck{}
