package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// HostIPCCheck verifies that pods do not share the host IPC namespace.
type HostIPCCheck struct{}

func (c *HostIPCCheck) ID() string      { return "CIS-5.2.6" }
func (c *HostIPCCheck) Name() string     { return "Minimize the admission of containers with hostIPC" }
func (c *HostIPCCheck) Description() string {
	return "Ensure that pods do not share the host IPC namespace"
}
func (c *HostIPCCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *HostIPCCheck) Benchmark() string         { return "CIS" }
func (c *HostIPCCheck) Section() string            { return "5.2.6" }

func (c *HostIPCCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runPodSpecCheck(ctx, client, c, func(pod corev1.Pod) *models.Evidence {
		if pod.Spec.HostIPC {
			return &models.Evidence{
				Message:  fmt.Sprintf("Pod '%s/%s' shares the host IPC namespace", pod.Namespace, pod.Name),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    "spec.hostIPC",
				Value:    "true",
			}
		}
		return nil
	})
}

var _ scanning.Check = &HostIPCCheck{}
