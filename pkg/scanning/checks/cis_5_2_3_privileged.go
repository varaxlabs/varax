package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// PrivilegedContainerCheck verifies that no pods run privileged containers.
type PrivilegedContainerCheck struct{}

func (c *PrivilegedContainerCheck) ID() string          { return "CIS-5.2.3" }
func (c *PrivilegedContainerCheck) Name() string        { return "Minimize the admission of privileged containers" }
func (c *PrivilegedContainerCheck) Description() string {
	return "Ensure that pods do not run with privileged security context"
}
func (c *PrivilegedContainerCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *PrivilegedContainerCheck) Benchmark() string         { return "CIS" }
func (c *PrivilegedContainerCheck) Section() string           { return "5.2.3" }

func (c *PrivilegedContainerCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			return &models.Evidence{
				Message: fmt.Sprintf("Container '%s' in pod '%s/%s' is privileged",
					container.Name, pod.Namespace, pod.Name),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    fmt.Sprintf("spec.containers[%s].securityContext.privileged", container.Name),
				Value:    "true",
			}
		}
		return nil
	})
}

var _ scanning.Check = &PrivilegedContainerCheck{}
