package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type SAKeyFileCheck struct{}

func (c *SAKeyFileCheck) ID() string          { return "CIS-1.2.22" }
func (c *SAKeyFileCheck) Name() string        { return "Ensure service account key file is set" }
func (c *SAKeyFileCheck) Description() string { return "Verify --service-account-key-file is set" }
func (c *SAKeyFileCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *SAKeyFileCheck) Benchmark() string         { return "CIS" }
func (c *SAKeyFileCheck) Section() string            { return "1.2.22" }

func (c *SAKeyFileCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		if hasArg(args, "--service-account-key-file") {
			return true, "Service account key file is set"
		}
		return false, "API server --service-account-key-file is not set"
	})
}

var _ scanning.Check = &SAKeyFileCheck{}
