package checks

import (
	"context"
	"fmt"

	"github.com/kubeshield/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = fmt.Sprintf("failed to list Pods: %v", err)
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		if pod.Spec.HostNetwork {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Pod '%s/%s' uses the host network",
					pod.Namespace, pod.Name),
				Resource: models.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Field: "spec.hostNetwork",
				Value: "true",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No pods use the host network in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d pod(s) using host network", len(evidence))
		result.Evidence = evidence
	}

	return result
}
