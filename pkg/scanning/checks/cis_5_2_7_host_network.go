package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// HostNetworkCheck verifies that pods do not use the host network.
type HostNetworkCheck struct{}

func (c *HostNetworkCheck) ID() string      { return "CIS-5.2.7" }
func (c *HostNetworkCheck) Name() string     { return "Minimize the admission of containers with hostNetwork" }
func (c *HostNetworkCheck) Description() string {
	return "Ensure that pods do not use the host network namespace"
}
func (c *HostNetworkCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *HostNetworkCheck) Benchmark() string         { return "CIS" }
func (c *HostNetworkCheck) Section() string            { return "5.2.7" }

func (c *HostNetworkCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runPodSpecCheck(ctx, client, c, func(pod corev1.Pod) *models.Evidence {
		if pod.Spec.HostNetwork {
			return &models.Evidence{
				Message:  fmt.Sprintf("Pod '%s/%s' uses the host network", pod.Namespace, pod.Name),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    "spec.hostNetwork",
				Value:    "true",
			}
		}
		return nil
	})
}

var _ scanning.Check = &HostNetworkCheck{}
