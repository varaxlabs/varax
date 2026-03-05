package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type AnonAuthCheck struct{}

func (c *AnonAuthCheck) ID() string          { return "CIS-1.2.1" }
func (c *AnonAuthCheck) Name() string        { return "Ensure anonymous auth is disabled" }
func (c *AnonAuthCheck) Description() string { return "Verify --anonymous-auth is set to false on the API server" }
func (c *AnonAuthCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *AnonAuthCheck) Benchmark() string         { return "CIS" }
func (c *AnonAuthCheck) Section() string            { return "1.2.1" }

func (c *AnonAuthCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--anonymous-auth")
		if ok && val == "false" {
			return true, "Anonymous authentication is disabled"
		}
		return false, "API server does not have --anonymous-auth=false"
	})
}

var _ scanning.Check = &AnonAuthCheck{}
