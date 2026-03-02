package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// DefaultServiceAccountCheck verifies that pods do not use the default service account.
type DefaultServiceAccountCheck struct{}

func (c *DefaultServiceAccountCheck) ID() string      { return "CIS-5.1.5" }
func (c *DefaultServiceAccountCheck) Name() string     { return "Ensure that default service accounts are not actively used" }
func (c *DefaultServiceAccountCheck) Description() string {
	return "Ensure that pods do not use the default service account"
}
func (c *DefaultServiceAccountCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *DefaultServiceAccountCheck) Benchmark() string         { return "CIS" }
func (c *DefaultServiceAccountCheck) Section() string            { return "5.1.5" }

func (c *DefaultServiceAccountCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	pods, err := scanning.ListPods(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list Pods"
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		if pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default" {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Pod '%s/%s' uses the default service account",
					pod.Namespace, pod.Name),
				Resource: models.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Field: "spec.serviceAccountName",
				Value: "default",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No pods use the default service account in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d pod(s) using the default service account", len(evidence))
		result.Evidence = evidence
	}

	return result
}
