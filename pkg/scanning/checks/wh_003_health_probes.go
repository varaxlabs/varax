package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// HealthProbesCheck verifies that containers have liveness and readiness probes defined.
type HealthProbesCheck struct{}

func (c *HealthProbesCheck) ID() string          { return "WH-003" }
func (c *HealthProbesCheck) Name() string        { return "Health Probes Defined" }
func (c *HealthProbesCheck) Description() string { return "Ensure containers have liveness and readiness probes defined for self-healing" }
func (c *HealthProbesCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *HealthProbesCheck) Benchmark() string         { return BenchmarkWorkloadHygiene }
func (c *HealthProbesCheck) Section() string           { return "3" }

func (c *HealthProbesCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		var missing []string

		if container.LivenessProbe == nil {
			missing = append(missing, "livenessProbe")
		}
		if container.ReadinessProbe == nil {
			missing = append(missing, "readinessProbe")
		}

		if len(missing) == 0 {
			return nil
		}

		return &models.Evidence{
			Message: fmt.Sprintf("Container '%s' in pod '%s/%s' is missing probes: %v",
				container.Name, pod.Namespace, pod.Name, missing),
			Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
			Field:    fmt.Sprintf("spec.containers[%s]", container.Name),
			Value:    fmt.Sprintf("missing: %v", missing),
		}
	})
}

var _ scanning.Check = &HealthProbesCheck{}
