package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
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
	result := baseResult(c)

	pods, err := scanning.ListPods(ctx, client, "default")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list Pods in default namespace"
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods {
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

var _ scanning.Check = &DefaultNamespaceCheck{}
