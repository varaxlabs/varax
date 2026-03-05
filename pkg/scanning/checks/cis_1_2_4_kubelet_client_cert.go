package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type KubeletClientCertCheck struct{}

func (c *KubeletClientCertCheck) ID() string      { return "CIS-1.2.4" }
func (c *KubeletClientCertCheck) Name() string    { return "Ensure kubelet client certificate and key are set" }
func (c *KubeletClientCertCheck) Description() string { return "Verify --kubelet-client-certificate and --kubelet-client-key are set" }
func (c *KubeletClientCertCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *KubeletClientCertCheck) Benchmark() string         { return "CIS" }
func (c *KubeletClientCertCheck) Section() string            { return "1.2.4" }

func (c *KubeletClientCertCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		hasCert := hasArg(args, "--kubelet-client-certificate")
		hasKey := hasArg(args, "--kubelet-client-key")
		if hasCert && hasKey {
			return true, "Kubelet client certificate and key are set"
		}
		return false, "API server missing --kubelet-client-certificate and/or --kubelet-client-key"
	})
}

var _ scanning.Check = &KubeletClientCertCheck{}
