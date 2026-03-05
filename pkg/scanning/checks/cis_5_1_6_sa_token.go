package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
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
	result := baseResult(c)

	serviceAccounts, err := scanning.ListServiceAccounts(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list ServiceAccounts"
		return result
	}

	var evidence []models.Evidence
	for _, sa := range serviceAccounts {
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

var _ scanning.Check = &SATokenAutoMountCheck{}
