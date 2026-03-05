package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// HostPIDCheck verifies that pods do not share the host PID namespace.
type HostPIDCheck struct{}

func (c *HostPIDCheck) ID() string      { return "CIS-5.2.5" }
func (c *HostPIDCheck) Name() string     { return "Minimize the admission of containers with hostPID" }
func (c *HostPIDCheck) Description() string {
	return "Ensure that pods do not share the host process ID namespace"
}
func (c *HostPIDCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *HostPIDCheck) Benchmark() string         { return "CIS" }
func (c *HostPIDCheck) Section() string            { return "5.2.5" }

func (c *HostPIDCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runPodSpecCheck(ctx, client, c, func(pod corev1.Pod) *models.Evidence {
		if pod.Spec.HostPID {
			return &models.Evidence{
				Message:  fmt.Sprintf("Pod '%s/%s' shares the host PID namespace", pod.Namespace, pod.Name),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    "spec.hostPID",
				Value:    "true",
			}
		}
		return nil
	})
}

var _ scanning.Check = &HostPIDCheck{}
