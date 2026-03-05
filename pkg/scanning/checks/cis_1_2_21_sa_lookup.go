package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type SALookupCheck struct{}

func (c *SALookupCheck) ID() string          { return "CIS-1.2.21" }
func (c *SALookupCheck) Name() string        { return "Ensure service account lookup is enabled" }
func (c *SALookupCheck) Description() string { return "Verify --service-account-lookup is not set to false" }
func (c *SALookupCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *SALookupCheck) Benchmark() string         { return "CIS" }
func (c *SALookupCheck) Section() string            { return "1.2.21" }

func (c *SALookupCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--service-account-lookup")
		if ok && val == "false" {
			return false, "API server has --service-account-lookup=false"
		}
		return true, "Service account lookup is enabled"
	})
}

var _ scanning.Check = &SALookupCheck{}
