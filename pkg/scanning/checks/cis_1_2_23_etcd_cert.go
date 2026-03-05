package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type EtcdCertCheck struct{}

func (c *EtcdCertCheck) ID() string          { return "CIS-1.2.23" }
func (c *EtcdCertCheck) Name() string        { return "Ensure etcd certfile and keyfile are set" }
func (c *EtcdCertCheck) Description() string { return "Verify --etcd-certfile and --etcd-keyfile are set" }
func (c *EtcdCertCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *EtcdCertCheck) Benchmark() string         { return "CIS" }
func (c *EtcdCertCheck) Section() string            { return "1.2.23" }

func (c *EtcdCertCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		hasCert := hasArg(args, "--etcd-certfile")
		hasKey := hasArg(args, "--etcd-keyfile")
		if hasCert && hasKey {
			return true, "etcd certfile and keyfile are set"
		}
		return false, "API server missing --etcd-certfile and/or --etcd-keyfile"
	})
}

var _ scanning.Check = &EtcdCertCheck{}
