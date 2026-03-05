package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type CNINetworkPolicyCheck struct{}

func (c *CNINetworkPolicyCheck) ID() string      { return "CIS-5.3.1" }
func (c *CNINetworkPolicyCheck) Name() string    { return "Ensure CNI supports NetworkPolicy" }
func (c *CNINetworkPolicyCheck) Description() string { return "Verify that NetworkPolicy API is available in the cluster" }
func (c *CNINetworkPolicyCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *CNINetworkPolicyCheck) Benchmark() string         { return "CIS" }
func (c *CNINetworkPolicyCheck) Section() string            { return "5.3.1" }

func (c *CNINetworkPolicyCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	// Test that NetworkPolicy API is available by listing policies
	_, err := scanning.ListNetworkPolicies(ctx, client, "")
	if err != nil {
		result.Status = models.StatusFail
		result.Message = "NetworkPolicy API is not available — CNI may not support it"
		result.Evidence = []models.Evidence{{Message: err.Error()}}
		return result
	}

	result.Status = models.StatusPass
	result.Message = "NetworkPolicy API is available"
	return result
}

var _ scanning.Check = &CNINetworkPolicyCheck{}
