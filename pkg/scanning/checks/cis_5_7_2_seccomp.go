package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// SeccompCheck verifies that pods have a Seccomp profile set.
type SeccompCheck struct{}

func (c *SeccompCheck) ID() string      { return "CIS-5.7.2" }
func (c *SeccompCheck) Name() string     { return "Ensure that the Seccomp profile is set to RuntimeDefault or stronger" }
func (c *SeccompCheck) Description() string {
	return "Ensure that pods have a Seccomp profile configured"
}
func (c *SeccompCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *SeccompCheck) Benchmark() string         { return "CIS" }
func (c *SeccompCheck) Section() string            { return "5.7.2" }

func (c *SeccompCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

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

		hasProfile := false
		if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
			hasProfile = true
		}

		if !hasProfile {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Pod '%s/%s' does not have a Seccomp profile set",
					pod.Namespace, pod.Name),
				Resource: models.Resource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
				Field: "spec.securityContext.seccompProfile",
				Value: "not set",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All pods have a Seccomp profile set in non-system namespaces"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d pod(s) without a Seccomp profile", len(evidence))
		result.Evidence = evidence
	}

	return result
}

var _ scanning.Check = &SeccompCheck{}
