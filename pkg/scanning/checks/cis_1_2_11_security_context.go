package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type SecurityContextAdmissionCheck struct{}

func (c *SecurityContextAdmissionCheck) ID() string      { return "CIS-1.2.11" }
func (c *SecurityContextAdmissionCheck) Name() string    { return "Ensure PodSecurity or SecurityContextDeny admission is enabled" }
func (c *SecurityContextAdmissionCheck) Description() string { return "Verify PodSecurity or SecurityContextDeny admission is enabled" }
func (c *SecurityContextAdmissionCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *SecurityContextAdmissionCheck) Benchmark() string         { return "CIS" }
func (c *SecurityContextAdmissionCheck) Section() string            { return "1.2.11" }

func (c *SecurityContextAdmissionCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--enable-admission-plugins")
		if ok && (strings.Contains(val, "PodSecurity") || strings.Contains(val, "SecurityContextDeny")) {
			return true, "PodSecurity or SecurityContextDeny admission is enabled"
		}
		return false, "Neither PodSecurity nor SecurityContextDeny admission is enabled"
	})
}

var _ scanning.Check = &SecurityContextAdmissionCheck{}
