package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type ClientCACheck struct{}

func (c *ClientCACheck) ID() string          { return "CIS-1.2.25" }
func (c *ClientCACheck) Name() string        { return "Ensure client CA file is set" }
func (c *ClientCACheck) Description() string { return "Verify --client-ca-file is set on the API server" }
func (c *ClientCACheck) Severity() models.Severity { return models.SeverityHigh }
func (c *ClientCACheck) Benchmark() string         { return "CIS" }
func (c *ClientCACheck) Section() string            { return "1.2.25" }

func (c *ClientCACheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		if hasArg(args, "--client-ca-file") {
			return true, "Client CA file is set"
		}
		return false, "API server --client-ca-file is not set"
	})
}

var _ scanning.Check = &ClientCACheck{}
