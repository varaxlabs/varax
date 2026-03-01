package checks

import (
	"context"
	"fmt"

	"github.com/kubeshield/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DefaultNamespaceCheck verifies that no pods are running in the default namespace.
type DefaultNamespaceCheck struct{}

func (c *DefaultNamespaceCheck) ID() string      { return "CIS-5.7.4" }
func (c *DefaultNamespaceCheck) Name() string     { return "The default namespace should not be used" }
func (c *DefaultNamespaceCheck) Description() string {
	return "Ensure that pods are not deployed to the default namespace"
}
func (c *DefaultNamespaceCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *DefaultNamespaceCheck) Benchmark() string         { return "CIS" }
func (c *DefaultNamespaceCheck) Section() string            { return "5.7.4" }

func (c *DefaultNamespaceCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	pods, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = fmt.Sprintf("failed to list Pods in default namespace: %v", err)
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods.Items {
		evidence = append(evidence, models.Evidence{
			Message: fmt.Sprintf("Pod '%s' is running in the default namespace", pod.Name),
			Resource: models.Resource{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: "default",
			},
			Field: "metadata.namespace",
			Value: "default",
		})
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No pods are running in the default namespace"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d pod(s) in the default namespace", len(evidence))
		result.Evidence = evidence
	}

	return result
}
