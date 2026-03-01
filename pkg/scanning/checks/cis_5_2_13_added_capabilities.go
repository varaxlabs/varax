package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubeshield/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AddedCapabilitiesCheck verifies that containers do not add extra capabilities.
type AddedCapabilitiesCheck struct{}

func (c *AddedCapabilitiesCheck) ID() string      { return "CIS-5.2.13" }
func (c *AddedCapabilitiesCheck) Name() string     { return "Minimize the admission of containers with added capabilities" }
func (c *AddedCapabilitiesCheck) Description() string {
	return "Ensure that containers do not add additional Linux capabilities"
}
func (c *AddedCapabilitiesCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *AddedCapabilitiesCheck) Benchmark() string         { return "CIS" }
func (c *AddedCapabilitiesCheck) Section() string            { return "5.2.13" }

func (c *AddedCapabilitiesCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			if container.SecurityContext != nil &&
				container.SecurityContext.Capabilities != nil &&
				len(container.SecurityContext.Capabilities.Add) > 0 {
				caps := make([]string, len(container.SecurityContext.Capabilities.Add))
				for i, cap := range container.SecurityContext.Capabilities.Add {
					caps[i] = string(cap)
				}
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' adds capabilities: %s",
						container.Name, pod.Namespace, pod.Name, strings.Join(caps, ", ")),
					Resource: models.Resource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					},
					Field: fmt.Sprintf("spec.containers[%s].securityContext.capabilities.add", container.Name),
					Value: strings.Join(caps, ", "),
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No containers add capabilities in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) with added capabilities", len(evidence))
		result.Evidence = evidence
	}

	return result
}
