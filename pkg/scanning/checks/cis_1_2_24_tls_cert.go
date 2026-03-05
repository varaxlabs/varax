package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type TLSCertCheck struct{}

func (c *TLSCertCheck) ID() string          { return "CIS-1.2.24" }
func (c *TLSCertCheck) Name() string        { return "Ensure TLS cert and private key files are set" }
func (c *TLSCertCheck) Description() string { return "Verify --tls-cert-file and --tls-private-key-file are set" }
func (c *TLSCertCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *TLSCertCheck) Benchmark() string         { return "CIS" }
func (c *TLSCertCheck) Section() string            { return "1.2.24" }

func (c *TLSCertCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		hasCert := hasArg(args, "--tls-cert-file")
		hasKey := hasArg(args, "--tls-private-key-file")
		if hasCert && hasKey {
			return true, "TLS cert and private key files are set"
		}
		return false, "API server missing --tls-cert-file and/or --tls-private-key-file"
	})
}

var _ scanning.Check = &TLSCertCheck{}
