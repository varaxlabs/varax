package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// HostPortCheck verifies that containers do not use host ports.
type HostPortCheck struct{}

func (c *HostPortCheck) ID() string      { return "CIS-5.2.8" }
func (c *HostPortCheck) Name() string     { return "Minimize the admission of containers with hostPort" }
func (c *HostPortCheck) Description() string {
	return "Ensure that containers do not use host ports"
}
func (c *HostPortCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *HostPortCheck) Benchmark() string         { return "CIS" }
func (c *HostPortCheck) Section() string            { return "5.2.8" }

func (c *HostPortCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			for _, port := range container.Ports {
				if port.HostPort != 0 {
					evidence = append(evidence, models.Evidence{
						Message: fmt.Sprintf("Container '%s' in pod '%s/%s' uses hostPort %d",
							container.Name, pod.Namespace, pod.Name, port.HostPort),
						Resource: models.Resource{
							Kind:      "Pod",
							Name:      pod.Name,
							Namespace: pod.Namespace,
						},
						Field: fmt.Sprintf("spec.containers[%s].ports[].hostPort", container.Name),
						Value: fmt.Sprintf("%d", port.HostPort),
					})
				}
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No containers use host ports in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) using host ports", len(evidence))
		result.Evidence = evidence
	}

	return result
}
