package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type NoAlwaysAllowCheck struct{}

func (c *NoAlwaysAllowCheck) ID() string          { return "CIS-1.2.6" }
func (c *NoAlwaysAllowCheck) Name() string        { return "Ensure authorization mode excludes AlwaysAllow" }
func (c *NoAlwaysAllowCheck) Description() string { return "Verify --authorization-mode does not include AlwaysAllow" }
func (c *NoAlwaysAllowCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *NoAlwaysAllowCheck) Benchmark() string         { return "CIS" }
func (c *NoAlwaysAllowCheck) Section() string            { return "1.2.6" }

func (c *NoAlwaysAllowCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--authorization-mode")
		if !ok {
			return false, "API server --authorization-mode is not set"
		}
		if strings.Contains(val, "AlwaysAllow") {
			return false, "API server authorization mode includes AlwaysAllow"
		}
		return true, "Authorization mode does not include AlwaysAllow"
	})
}

var _ scanning.Check = &NoAlwaysAllowCheck{}
