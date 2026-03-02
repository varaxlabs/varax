package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// PrivilegedContainerCheck verifies that no pods run privileged containers.
type PrivilegedContainerCheck struct{}

func (c *PrivilegedContainerCheck) ID() string          { return "CIS-5.2.3" }
func (c *PrivilegedContainerCheck) Name() string         { return "Minimize the admission of privileged containers" }
func (c *PrivilegedContainerCheck) Description() string {
	return "Ensure that pods do not run with privileged security context"
}
func (c *PrivilegedContainerCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *PrivilegedContainerCheck) Benchmark() string         { return "CIS" }
func (c *PrivilegedContainerCheck) Section() string            { return "5.2.3" }

func (c *PrivilegedContainerCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			if container.SecurityContext != nil &&
				container.SecurityContext.Privileged != nil &&
				*container.SecurityContext.Privileged {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' is privileged",
						container.Name, pod.Namespace, pod.Name),
					Resource: models.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Field: fmt.Sprintf("spec.containers[%s].securityContext.privileged", container.Name),
					Value: "true",
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No privileged containers found in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d privileged container(s)", len(evidence))
		result.Evidence = evidence
	}

	return result
}
