package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type ServiceAccountAdmissionCheck struct{}

func (c *ServiceAccountAdmissionCheck) ID() string      { return "CIS-1.2.12" }
func (c *ServiceAccountAdmissionCheck) Name() string    { return "Ensure ServiceAccount admission is enabled" }
func (c *ServiceAccountAdmissionCheck) Description() string { return "Verify ServiceAccount admission controller is enabled" }
func (c *ServiceAccountAdmissionCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *ServiceAccountAdmissionCheck) Benchmark() string         { return "CIS" }
func (c *ServiceAccountAdmissionCheck) Section() string            { return "1.2.12" }

func (c *ServiceAccountAdmissionCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		// ServiceAccount is enabled by default unless explicitly disabled
		val, ok := getArgValue(args, "--disable-admission-plugins")
		if ok && strings.Contains(val, "ServiceAccount") {
			return false, "ServiceAccount admission plugin is explicitly disabled"
		}
		return true, "ServiceAccount admission plugin is enabled"
	})
}

var _ scanning.Check = &ServiceAccountAdmissionCheck{}
