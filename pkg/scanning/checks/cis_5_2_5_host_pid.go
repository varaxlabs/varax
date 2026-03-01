package checks

import (
	"context"
	"fmt"

	"github.com/kubeshield/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

		if pod.Spec.HostPID {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Pod '%s/%s' shares the host PID namespace",
					pod.Namespace, pod.Name),
				Resource: models.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Field: "spec.hostPID",
				Value: "true",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No pods share the host PID namespace in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d pod(s) sharing host PID namespace", len(evidence))
		result.Evidence = evidence
	}

	return result
}
