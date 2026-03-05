package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// AddedCapabilitiesCheck verifies that containers do not add extra capabilities.
type AddedCapabilitiesCheck struct{}

func (c *AddedCapabilitiesCheck) ID() string      { return "CIS-5.2.13" }
func (c *AddedCapabilitiesCheck) Name() string    { return "Minimize the admission of containers with added capabilities" }
func (c *AddedCapabilitiesCheck) Description() string {
	return "Ensure that containers do not add additional Linux capabilities"
}
func (c *AddedCapabilitiesCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *AddedCapabilitiesCheck) Benchmark() string         { return "CIS" }
func (c *AddedCapabilitiesCheck) Section() string           { return "5.2.13" }

func (c *AddedCapabilitiesCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		if container.SecurityContext != nil &&
			container.SecurityContext.Capabilities != nil &&
			len(container.SecurityContext.Capabilities.Add) > 0 {
			caps := make([]string, len(container.SecurityContext.Capabilities.Add))
			for i, cap := range container.SecurityContext.Capabilities.Add {
				caps[i] = string(cap)
			}
			return &models.Evidence{
				Message: fmt.Sprintf("Container '%s' in pod '%s/%s' adds capabilities: %s",
					container.Name, pod.Namespace, pod.Name, strings.Join(caps, ", ")),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    fmt.Sprintf("spec.containers[%s].securityContext.capabilities.add", container.Name),
				Value:    strings.Join(caps, ", "),
			}
		}
		return nil
	})
}

var _ scanning.Check = &AddedCapabilitiesCheck{}
