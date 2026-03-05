package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// DropCapabilitiesCheck verifies that containers drop all capabilities.
type DropCapabilitiesCheck struct{}

func (c *DropCapabilitiesCheck) ID() string      { return "CIS-5.2.4" }
func (c *DropCapabilitiesCheck) Name() string    { return "Minimize the admission of containers without dropping ALL capabilities" }
func (c *DropCapabilitiesCheck) Description() string {
	return "Ensure that containers drop ALL capabilities in their security context"
}
func (c *DropCapabilitiesCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *DropCapabilitiesCheck) Benchmark() string         { return "CIS" }
func (c *DropCapabilitiesCheck) Section() string           { return "5.2.4" }

func (c *DropCapabilitiesCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		if !dropsAllCapabilities(container) {
			return &models.Evidence{
				Message: fmt.Sprintf("Container '%s' in pod '%s/%s' does not drop ALL capabilities",
					container.Name, pod.Namespace, pod.Name),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    fmt.Sprintf("spec.containers[%s].securityContext.capabilities.drop", container.Name),
				Value:    "missing ALL",
			}
		}
		return nil
	})
}

var _ scanning.Check = &DropCapabilitiesCheck{}

func dropsAllCapabilities(container corev1.Container) bool {
	if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
		return false
	}
	for _, cap := range container.SecurityContext.Capabilities.Drop {
		if cap == "ALL" {
			return true
		}
	}
	return false
}
