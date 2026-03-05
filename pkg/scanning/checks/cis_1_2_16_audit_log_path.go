package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type AuditLogPathCheck struct{}

func (c *AuditLogPathCheck) ID() string          { return "CIS-1.2.16" }
func (c *AuditLogPathCheck) Name() string        { return "Ensure audit log path is set" }
func (c *AuditLogPathCheck) Description() string { return "Verify --audit-log-path is set on the API server" }
func (c *AuditLogPathCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *AuditLogPathCheck) Benchmark() string         { return "CIS" }
func (c *AuditLogPathCheck) Section() string            { return "1.2.16" }

func (c *AuditLogPathCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		if hasArg(args, "--audit-log-path") {
			return true, "Audit log path is set"
		}
		return false, "API server --audit-log-path is not set"
	})
}

var _ scanning.Check = &AuditLogPathCheck{}
