package checks

import (
	"context"
	"strconv"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type AuditLogMaxAgeCheck struct{}

func (c *AuditLogMaxAgeCheck) ID() string          { return "CIS-1.2.17" }
func (c *AuditLogMaxAgeCheck) Name() string        { return "Ensure audit log max age is at least 30 days" }
func (c *AuditLogMaxAgeCheck) Description() string { return "Verify --audit-log-maxage is set to 30 or more" }
func (c *AuditLogMaxAgeCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *AuditLogMaxAgeCheck) Benchmark() string         { return "CIS" }
func (c *AuditLogMaxAgeCheck) Section() string            { return "1.2.17" }

func (c *AuditLogMaxAgeCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--audit-log-maxage")
		if !ok {
			return false, "API server --audit-log-maxage is not set"
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 30 {
			return false, "API server --audit-log-maxage is less than 30"
		}
		return true, "Audit log max age is at least 30 days"
	})
}

var _ scanning.Check = &AuditLogMaxAgeCheck{}
