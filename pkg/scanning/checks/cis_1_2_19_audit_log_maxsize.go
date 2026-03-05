package checks

import (
	"context"
	"strconv"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type AuditLogMaxSizeCheck struct{}

func (c *AuditLogMaxSizeCheck) ID() string          { return "CIS-1.2.19" }
func (c *AuditLogMaxSizeCheck) Name() string        { return "Ensure audit log max size is at least 100MB" }
func (c *AuditLogMaxSizeCheck) Description() string { return "Verify --audit-log-maxsize is set to 100 or more" }
func (c *AuditLogMaxSizeCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *AuditLogMaxSizeCheck) Benchmark() string         { return "CIS" }
func (c *AuditLogMaxSizeCheck) Section() string            { return "1.2.19" }

func (c *AuditLogMaxSizeCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--audit-log-maxsize")
		if !ok {
			return false, "API server --audit-log-maxsize is not set"
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 100 {
			return false, "API server --audit-log-maxsize is less than 100"
		}
		return true, "Audit log max size is at least 100MB"
	})
}

var _ scanning.Check = &AuditLogMaxSizeCheck{}
