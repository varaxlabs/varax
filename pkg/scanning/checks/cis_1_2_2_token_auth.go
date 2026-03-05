package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type TokenAuthCheck struct{}

func (c *TokenAuthCheck) ID() string          { return "CIS-1.2.2" }
func (c *TokenAuthCheck) Name() string        { return "Ensure token auth file is not set" }
func (c *TokenAuthCheck) Description() string { return "Verify --token-auth-file is not set on the API server" }
func (c *TokenAuthCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *TokenAuthCheck) Benchmark() string         { return "CIS" }
func (c *TokenAuthCheck) Section() string            { return "1.2.2" }

func (c *TokenAuthCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		if hasArg(args, "--token-auth-file") {
			return false, "API server has --token-auth-file set (static token authentication)"
		}
		return true, "--token-auth-file is not set"
	})
}

var _ scanning.Check = &TokenAuthCheck{}
