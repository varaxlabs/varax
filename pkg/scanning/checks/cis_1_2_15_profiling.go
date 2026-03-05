package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type APIServerProfilingCheck struct{}

func (c *APIServerProfilingCheck) ID() string      { return "CIS-1.2.15" }
func (c *APIServerProfilingCheck) Name() string    { return "Ensure API server profiling is disabled" }
func (c *APIServerProfilingCheck) Description() string { return "Verify --profiling is set to false on the API server" }
func (c *APIServerProfilingCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *APIServerProfilingCheck) Benchmark() string         { return "CIS" }
func (c *APIServerProfilingCheck) Section() string            { return "1.2.15" }

func (c *APIServerProfilingCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--profiling")
		if ok && val == "false" {
			return true, "API server profiling is disabled"
		}
		return false, "API server does not have --profiling=false"
	})
}

var _ scanning.Check = &APIServerProfilingCheck{}
