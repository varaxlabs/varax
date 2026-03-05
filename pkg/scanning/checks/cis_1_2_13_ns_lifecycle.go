package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type NamespaceLifecycleCheck struct{}

func (c *NamespaceLifecycleCheck) ID() string      { return "CIS-1.2.13" }
func (c *NamespaceLifecycleCheck) Name() string    { return "Ensure NamespaceLifecycle admission is enabled" }
func (c *NamespaceLifecycleCheck) Description() string { return "Verify NamespaceLifecycle admission controller is enabled" }
func (c *NamespaceLifecycleCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *NamespaceLifecycleCheck) Benchmark() string         { return "CIS" }
func (c *NamespaceLifecycleCheck) Section() string            { return "1.2.13" }

func (c *NamespaceLifecycleCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--disable-admission-plugins")
		if ok && strings.Contains(val, "NamespaceLifecycle") {
			return false, "NamespaceLifecycle admission plugin is explicitly disabled"
		}
		return true, "NamespaceLifecycle admission plugin is enabled"
	})
}

var _ scanning.Check = &NamespaceLifecycleCheck{}
