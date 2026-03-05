package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// SecurityContextCheck verifies that all containers have a SecurityContext defined.
type SecurityContextCheck struct{}

func (c *SecurityContextCheck) ID() string      { return "CIS-5.7.3" }
func (c *SecurityContextCheck) Name() string     { return "Apply SecurityContext to pods and containers" }
func (c *SecurityContextCheck) Description() string {
	return "Ensure that all containers have a SecurityContext defined"
}
func (c *SecurityContextCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *SecurityContextCheck) Benchmark() string         { return "CIS" }
func (c *SecurityContextCheck) Section() string            { return "5.7.3" }

func (c *SecurityContextCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

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
			if container.SecurityContext == nil {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' has no SecurityContext",
						container.Name, pod.Namespace, pod.Name),
					Resource: models.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Field: fmt.Sprintf("spec.containers[%s].securityContext", container.Name),
					Value: "nil",
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All containers have SecurityContext defined in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) without SecurityContext", len(evidence))
		result.Evidence = evidence
	}

	return result
}

var _ scanning.Check = &SecurityContextCheck{}
