package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// HostPortCheck verifies that containers do not use host ports.
type HostPortCheck struct{}

func (c *HostPortCheck) ID() string      { return "CIS-5.2.8" }
func (c *HostPortCheck) Name() string    { return "Minimize the admission of containers with hostPort" }
func (c *HostPortCheck) Description() string {
	return "Ensure that containers do not use host ports"
}
func (c *HostPortCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *HostPortCheck) Benchmark() string         { return "CIS" }
func (c *HostPortCheck) Section() string           { return "5.2.8" }

func (c *HostPortCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		for _, port := range container.Ports {
			if port.HostPort != 0 {
				return &models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' uses hostPort %d",
						container.Name, pod.Namespace, pod.Name, port.HostPort),
					Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
					Field:    fmt.Sprintf("spec.containers[%s].ports[].hostPort", container.Name),
					Value:    fmt.Sprintf("%d", port.HostPort),
				}
			}
		}
		return nil
	})
}

var _ scanning.Check = &HostPortCheck{}
