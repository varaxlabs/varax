package checks

import (
	"context"
	"fmt"

	"github.com/kubeshield/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

		if pod.Spec.HostIPC {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Pod '%s/%s' shares the host IPC namespace",
					pod.Namespace, pod.Name),
				Resource: models.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Field: "spec.hostIPC",
				Value: "true",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No pods share the host IPC namespace in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d pod(s) sharing host IPC namespace", len(evidence))
		result.Evidence = evidence
	}

	return result
}
