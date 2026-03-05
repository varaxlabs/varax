package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type KubeletCACheck struct{}

func (c *KubeletCACheck) ID() string          { return "CIS-1.2.5" }
func (c *KubeletCACheck) Name() string        { return "Ensure kubelet certificate authority is set" }
func (c *KubeletCACheck) Description() string { return "Verify --kubelet-certificate-authority is set" }
func (c *KubeletCACheck) Severity() models.Severity { return models.SeverityHigh }
func (c *KubeletCACheck) Benchmark() string         { return "CIS" }
func (c *KubeletCACheck) Section() string            { return "1.2.5" }

func (c *KubeletCACheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		if hasArg(args, "--kubelet-certificate-authority") {
			return true, "Kubelet certificate authority is set"
		}
		return false, "API server missing --kubelet-certificate-authority"
	})
}

var _ scanning.Check = &KubeletCACheck{}
