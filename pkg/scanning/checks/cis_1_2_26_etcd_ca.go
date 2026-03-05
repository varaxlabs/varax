package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type EtcdCACheck struct{}

func (c *EtcdCACheck) ID() string          { return "CIS-1.2.26" }
func (c *EtcdCACheck) Name() string        { return "Ensure etcd CA file is set" }
func (c *EtcdCACheck) Description() string { return "Verify --etcd-cafile is set on the API server" }
func (c *EtcdCACheck) Severity() models.Severity { return models.SeverityHigh }
func (c *EtcdCACheck) Benchmark() string         { return "CIS" }
func (c *EtcdCACheck) Section() string            { return "1.2.26" }

func (c *EtcdCACheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		if hasArg(args, "--etcd-cafile") {
			return true, "etcd CA file is set"
		}
		return false, "API server --etcd-cafile is not set"
	})
}

var _ scanning.Check = &EtcdCACheck{}
