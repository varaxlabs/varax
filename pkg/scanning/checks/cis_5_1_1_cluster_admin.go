package checks

import (
	"context"
	"fmt"

	"github.com/kubeshield/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ClusterAdminCheck verifies that cluster-admin ClusterRole is not excessively bound.
type ClusterAdminCheck struct{}

func (c *ClusterAdminCheck) ID() string          { return "CIS-5.1.1" }
func (c *ClusterAdminCheck) Name() string         { return "Restrict cluster-admin role binding" }
func (c *ClusterAdminCheck) Description() string {
	return "Ensure cluster-admin ClusterRoleBinding is restricted to legitimate admin accounts"
}
func (c *ClusterAdminCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *ClusterAdminCheck) Benchmark() string         { return "CIS" }
func (c *ClusterAdminCheck) Section() string            { return "5.1.1" }

func (c *ClusterAdminCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	bindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = fmt.Sprintf("failed to list ClusterRoleBindings: %v", err)
		return result
	}

	var evidence []models.Evidence
	for _, binding := range bindings.Items {
		if binding.RoleRef.Name != "cluster-admin" {
			continue
		}

		// Allow system-managed bindings
		if binding.Name == "system:masters" {
			continue
		}

		for _, subject := range binding.Subjects {
			// Flag non-group subjects or custom groups bound to cluster-admin
			if subject.Kind == "ServiceAccount" || subject.Kind == "User" {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("%s '%s' is bound to cluster-admin via ClusterRoleBinding '%s'",
						subject.Kind, subject.Name, binding.Name),
					Resource: models.Resource{
						Kind:      "ClusterRoleBinding",
						Name:      binding.Name,
						Namespace: subject.Namespace,
					},
					Field: "subjects",
					Value: fmt.Sprintf("%s/%s", subject.Kind, subject.Name),
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No excessive cluster-admin bindings found"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d excessive cluster-admin binding(s)", len(evidence))
		result.Evidence = evidence
	}

	return result
}
