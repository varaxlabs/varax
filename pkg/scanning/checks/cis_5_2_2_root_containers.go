package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// RootContainerCheck verifies that containers run as non-root.
type RootContainerCheck struct{}

func (c *RootContainerCheck) ID() string      { return "CIS-5.2.2" }
func (c *RootContainerCheck) Name() string    { return "Minimize the admission of root containers" }
func (c *RootContainerCheck) Description() string {
	return "Ensure that containers do not run as root user"
}
func (c *RootContainerCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *RootContainerCheck) Benchmark() string         { return "CIS" }
func (c *RootContainerCheck) Section() string           { return "5.2.2" }

func (c *RootContainerCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		if container.SecurityContext == nil ||
			container.SecurityContext.RunAsNonRoot == nil ||
			!*container.SecurityContext.RunAsNonRoot {
			return &models.Evidence{
				Message: fmt.Sprintf("Container '%s' in pod '%s/%s' does not enforce runAsNonRoot",
					container.Name, pod.Namespace, pod.Name),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    fmt.Sprintf("spec.containers[%s].securityContext.runAsNonRoot", container.Name),
				Value:    "false or unset",
			}
		}
		return nil
	})
}

var _ scanning.Check = &RootContainerCheck{}
