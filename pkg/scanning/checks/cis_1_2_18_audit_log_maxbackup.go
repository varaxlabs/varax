package checks

import (
	"context"
	"strconv"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type AuditLogMaxBackupCheck struct{}

func (c *AuditLogMaxBackupCheck) ID() string          { return "CIS-1.2.18" }
func (c *AuditLogMaxBackupCheck) Name() string        { return "Ensure audit log max backup is at least 10" }
func (c *AuditLogMaxBackupCheck) Description() string { return "Verify --audit-log-maxbackup is set to 10 or more" }
func (c *AuditLogMaxBackupCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *AuditLogMaxBackupCheck) Benchmark() string         { return "CIS" }
func (c *AuditLogMaxBackupCheck) Section() string            { return "1.2.18" }

func (c *AuditLogMaxBackupCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--audit-log-maxbackup")
		if !ok {
			return false, "API server --audit-log-maxbackup is not set"
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 10 {
			return false, "API server --audit-log-maxbackup is less than 10"
		}
		return true, "Audit log max backup is at least 10"
	})
}

var _ scanning.Check = &AuditLogMaxBackupCheck{}
