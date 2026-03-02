package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// PrivilegeEscalationCheck verifies that containers do not allow privilege escalation.
type PrivilegeEscalationCheck struct{}

func (c *PrivilegeEscalationCheck) ID() string      { return "CIS-5.2.1" }
func (c *PrivilegeEscalationCheck) Name() string     { return "Minimize the admission of containers with allowPrivilegeEscalation" }
func (c *PrivilegeEscalationCheck) Description() string {
	return "Ensure that containers do not allow privilege escalation"
}
func (c *PrivilegeEscalationCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *PrivilegeEscalationCheck) Benchmark() string         { return "CIS" }
func (c *PrivilegeEscalationCheck) Section() string            { return "5.2.1" }

func (c *PrivilegeEscalationCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	pods, err := scanning.ListPods(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list Pods"
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		containers := allContainers(pod)
		for _, container := range containers {
			if container.SecurityContext == nil ||
				container.SecurityContext.AllowPrivilegeEscalation == nil ||
				*container.SecurityContext.AllowPrivilegeEscalation {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' allows privilege escalation",
						container.Name, pod.Namespace, pod.Name),
					Resource: models.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Field: fmt.Sprintf("spec.containers[%s].securityContext.allowPrivilegeEscalation", container.Name),
					Value: "true or unset",
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No containers allow privilege escalation in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) allowing privilege escalation", len(evidence))
		result.Evidence = evidence
	}

	return result
}
