package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type DenyServiceExternalIPsCheck struct{}

func (c *DenyServiceExternalIPsCheck) ID() string      { return "CIS-1.2.3" }
func (c *DenyServiceExternalIPsCheck) Name() string    { return "Ensure DenyServiceExternalIPs admission is enabled" }
func (c *DenyServiceExternalIPsCheck) Description() string { return "Verify DenyServiceExternalIPs admission controller is enabled" }
func (c *DenyServiceExternalIPsCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *DenyServiceExternalIPsCheck) Benchmark() string         { return "CIS" }
func (c *DenyServiceExternalIPsCheck) Section() string            { return "1.2.3" }

func (c *DenyServiceExternalIPsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--enable-admission-plugins")
		if ok && strings.Contains(val, "DenyServiceExternalIPs") {
			return true, "DenyServiceExternalIPs admission plugin is enabled"
		}
		return false, "DenyServiceExternalIPs admission plugin is not enabled"
	})
}

var _ scanning.Check = &DenyServiceExternalIPsCheck{}
