package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// Section 3 — Control Plane Configuration

type NoStaticTokensCheck struct{}

func (c *NoStaticTokensCheck) ID() string      { return "CIS-3.1" }
func (c *NoStaticTokensCheck) Name() string    { return "Ensure authentication does not use static tokens" }
func (c *NoStaticTokensCheck) Description() string { return "Verify API server does not use static token or basic auth" }
func (c *NoStaticTokensCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *NoStaticTokensCheck) Benchmark() string         { return "CIS" }
func (c *NoStaticTokensCheck) Section() string            { return "3.1" }

func (c *NoStaticTokensCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		if hasArg(args, "--token-auth-file") {
			return false, "API server uses static token authentication"
		}
		if hasArg(args, "--basic-auth-file") {
			return false, "API server uses basic authentication"
		}
		return true, "No static token or basic auth files configured"
	})
}

type AuditPolicyCheck struct{}

func (c *AuditPolicyCheck) ID() string          { return "CIS-3.2" }
func (c *AuditPolicyCheck) Name() string        { return "Ensure audit policy covers required events" }
func (c *AuditPolicyCheck) Description() string { return "Verify --audit-policy-file is set on the API server" }
func (c *AuditPolicyCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *AuditPolicyCheck) Benchmark() string         { return "CIS" }
func (c *AuditPolicyCheck) Section() string            { return "3.2" }

func (c *AuditPolicyCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		if hasArg(args, "--audit-policy-file") {
			return true, "Audit policy file is configured"
		}
		return false, "API server --audit-policy-file is not set"
	})
}

var (
	_ scanning.Check = &NoStaticTokensCheck{}
	_ scanning.Check = &AuditPolicyCheck{}
)
