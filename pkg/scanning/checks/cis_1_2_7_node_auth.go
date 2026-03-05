package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type NodeAuthCheck struct{}

func (c *NodeAuthCheck) ID() string          { return "CIS-1.2.7" }
func (c *NodeAuthCheck) Name() string        { return "Ensure authorization mode includes Node" }
func (c *NodeAuthCheck) Description() string { return "Verify --authorization-mode includes Node" }
func (c *NodeAuthCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *NodeAuthCheck) Benchmark() string         { return "CIS" }
func (c *NodeAuthCheck) Section() string            { return "1.2.7" }

func (c *NodeAuthCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--authorization-mode")
		if ok && strings.Contains(val, "Node") {
			return true, "Authorization mode includes Node"
		}
		return false, "API server authorization mode does not include Node"
	})
}

var _ scanning.Check = &NodeAuthCheck{}
