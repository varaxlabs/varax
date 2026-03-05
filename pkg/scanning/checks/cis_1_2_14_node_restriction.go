package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type NodeRestrictionCheck struct{}

func (c *NodeRestrictionCheck) ID() string      { return "CIS-1.2.14" }
func (c *NodeRestrictionCheck) Name() string    { return "Ensure NodeRestriction admission is enabled" }
func (c *NodeRestrictionCheck) Description() string { return "Verify NodeRestriction admission controller is enabled" }
func (c *NodeRestrictionCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *NodeRestrictionCheck) Benchmark() string         { return "CIS" }
func (c *NodeRestrictionCheck) Section() string            { return "1.2.14" }

func (c *NodeRestrictionCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--enable-admission-plugins")
		if ok && strings.Contains(val, "NodeRestriction") {
			return true, "NodeRestriction admission plugin is enabled"
		}
		return false, "NodeRestriction admission plugin is not enabled"
	})
}

var _ scanning.Check = &NodeRestrictionCheck{}
