package checks

import (
	"context"
	"fmt"

	"github.com/kubeshield/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// SATokenAutoMountCheck verifies that service accounts disable automounting of API tokens.
type SATokenAutoMountCheck struct{}

func (c *SATokenAutoMountCheck) ID() string          { return "CIS-5.1.6" }
func (c *SATokenAutoMountCheck) Name() string         { return "Ensure SA tokens are not automatically mounted" }
func (c *SATokenAutoMountCheck) Description() string {
	return "Service accounts should set automountServiceAccountToken to false unless API access is required"
}
func (c *SATokenAutoMountCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *SATokenAutoMountCheck) Benchmark() string         { return "CIS" }
func (c *SATokenAutoMountCheck) Section() string            { return "5.1.6" }

func (c *SATokenAutoMountCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	serviceAccounts, err := client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = fmt.Sprintf("failed to list ServiceAccounts: %v", err)
		return result
	}

	var evidence []models.Evidence
	for _, sa := range serviceAccounts.Items {
		if isSystemNamespace(sa.Namespace) {
			continue
		}

		// Skip the 'default' SA if it hasn't been modified — it's the system default
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("ServiceAccount '%s/%s' has automountServiceAccountToken enabled or unset",
					sa.Namespace, sa.Name),
				Resource: models.Resource{
					Kind:      "ServiceAccount",
					Name:      sa.Name,
					Namespace: sa.Namespace,
				},
				Field: "automountServiceAccountToken",
				Value: "true (or unset)",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All non-system service accounts have automount disabled"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d service account(s) with automount enabled", len(evidence))
		result.Evidence = evidence
	}

	return result
}
