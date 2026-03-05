package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type RBACAuthCheck struct{}

func (c *RBACAuthCheck) ID() string          { return "CIS-1.2.8" }
func (c *RBACAuthCheck) Name() string        { return "Ensure authorization mode includes RBAC" }
func (c *RBACAuthCheck) Description() string { return "Verify --authorization-mode includes RBAC" }
func (c *RBACAuthCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *RBACAuthCheck) Benchmark() string         { return "CIS" }
func (c *RBACAuthCheck) Section() string            { return "1.2.8" }

func (c *RBACAuthCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--authorization-mode")
		if ok && strings.Contains(val, "RBAC") {
			return true, "Authorization mode includes RBAC"
		}
		return false, "API server authorization mode does not include RBAC"
	})
}

var _ scanning.Check = &RBACAuthCheck{}
