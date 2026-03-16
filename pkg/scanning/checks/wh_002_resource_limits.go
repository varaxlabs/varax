package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// ResourceLimitsCheck verifies that all containers have CPU and memory
// limits and requests defined.
type ResourceLimitsCheck struct{}

func (c *ResourceLimitsCheck) ID() string          { return "WH-002" }
func (c *ResourceLimitsCheck) Name() string        { return "Resource Limits Defined" }
func (c *ResourceLimitsCheck) Description() string { return "Ensure all containers have CPU and memory limits and requests defined" }
func (c *ResourceLimitsCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *ResourceLimitsCheck) Benchmark() string         { return BenchmarkWorkloadHygiene }
func (c *ResourceLimitsCheck) Section() string           { return "2" }

func (c *ResourceLimitsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		var missing []string

		if container.Resources.Limits.Cpu().IsZero() {
			missing = append(missing, "limits.cpu")
		}
		if container.Resources.Limits.Memory().IsZero() {
			missing = append(missing, "limits.memory")
		}
		if container.Resources.Requests.Cpu().IsZero() {
			missing = append(missing, "requests.cpu")
		}
		if container.Resources.Requests.Memory().IsZero() {
			missing = append(missing, "requests.memory")
		}

		if len(missing) == 0 {
			return nil
		}

		return &models.Evidence{
			Message: fmt.Sprintf("Container '%s' in pod '%s/%s' is missing resource specs: %v",
				container.Name, pod.Namespace, pod.Name, missing),
			Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
			Field:    fmt.Sprintf("spec.containers[%s].resources", container.Name),
			Value:    fmt.Sprintf("missing: %v", missing),
		}
	})
}

var _ scanning.Check = &ResourceLimitsCheck{}
