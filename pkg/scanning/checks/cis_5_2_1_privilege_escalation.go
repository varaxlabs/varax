package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// PrivilegeEscalationCheck verifies that containers do not allow privilege escalation.
type PrivilegeEscalationCheck struct{}

func (c *PrivilegeEscalationCheck) ID() string      { return "CIS-5.2.1" }
func (c *PrivilegeEscalationCheck) Name() string    { return "Minimize the admission of containers with allowPrivilegeEscalation" }
func (c *PrivilegeEscalationCheck) Description() string {
	return "Ensure that containers do not allow privilege escalation"
}
func (c *PrivilegeEscalationCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *PrivilegeEscalationCheck) Benchmark() string         { return "CIS" }
func (c *PrivilegeEscalationCheck) Section() string           { return "5.2.1" }

func (c *PrivilegeEscalationCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		if container.SecurityContext == nil ||
			container.SecurityContext.AllowPrivilegeEscalation == nil ||
			*container.SecurityContext.AllowPrivilegeEscalation {
			return &models.Evidence{
				Message: fmt.Sprintf("Container '%s' in pod '%s/%s' allows privilege escalation",
					container.Name, pod.Namespace, pod.Name),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    fmt.Sprintf("spec.containers[%s].securityContext.allowPrivilegeEscalation", container.Name),
				Value:    "true or unset",
			}
		}
		return nil
	})
}

var _ scanning.Check = &PrivilegeEscalationCheck{}
