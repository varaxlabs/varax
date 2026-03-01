package checks

import (
	"context"
	"fmt"

	"github.com/kubeshield/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// RootContainerCheck verifies that containers run as non-root.
type RootContainerCheck struct{}

func (c *RootContainerCheck) ID() string      { return "CIS-5.2.2" }
func (c *RootContainerCheck) Name() string     { return "Minimize the admission of root containers" }
func (c *RootContainerCheck) Description() string {
	return "Ensure that containers do not run as root user"
}
func (c *RootContainerCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *RootContainerCheck) Benchmark() string         { return "CIS" }
func (c *RootContainerCheck) Section() string            { return "5.2.2" }

func (c *RootContainerCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = fmt.Sprintf("failed to list Pods: %v", err)
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		containers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
		for _, container := range containers {
			if container.SecurityContext == nil ||
				container.SecurityContext.RunAsNonRoot == nil ||
				!*container.SecurityContext.RunAsNonRoot {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' does not enforce runAsNonRoot",
						container.Name, pod.Namespace, pod.Name),
					Resource: models.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Field: fmt.Sprintf("spec.containers[%s].securityContext.runAsNonRoot", container.Name),
					Value: "false or unset",
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All containers enforce runAsNonRoot in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) not enforcing runAsNonRoot", len(evidence))
		result.Evidence = evidence
	}

	return result
}
