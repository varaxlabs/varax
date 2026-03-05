package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type RequestTimeoutCheck struct{}

func (c *RequestTimeoutCheck) ID() string          { return "CIS-1.2.20" }
func (c *RequestTimeoutCheck) Name() string        { return "Ensure request timeout is set appropriately" }
func (c *RequestTimeoutCheck) Description() string { return "Verify --request-timeout is set on the API server" }
func (c *RequestTimeoutCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *RequestTimeoutCheck) Benchmark() string         { return "CIS" }
func (c *RequestTimeoutCheck) Section() string            { return "1.2.20" }

func (c *RequestTimeoutCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--request-timeout")
		if !ok {
			// Default timeout is acceptable
			return true, "Using default request timeout"
		}
		if val == "0" || val == "0s" {
			return false, "API server --request-timeout is set to 0 (no timeout)"
		}
		return true, "Request timeout is set appropriately"
	})
}

var _ scanning.Check = &RequestTimeoutCheck{}
