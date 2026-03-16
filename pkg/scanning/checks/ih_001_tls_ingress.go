package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// TLSIngressCheck verifies that all Ingress resources have TLS configured.
type TLSIngressCheck struct{}

func (c *TLSIngressCheck) ID() string          { return "IH-001" }
func (c *TLSIngressCheck) Name() string        { return "TLS on Ingress" }
func (c *TLSIngressCheck) Description() string { return "Ensure all Ingress resources have TLS configured — no plaintext HTTP exposure" }
func (c *TLSIngressCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *TLSIngressCheck) Benchmark() string         { return BenchmarkIngressHardening }
func (c *TLSIngressCheck) Section() string           { return "1" }

func (c *TLSIngressCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	ingresses, err := scanning.ListIngresses(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list ingresses"
		return result
	}

	if len(ingresses) == 0 {
		result.Status = models.StatusPass
		result.Message = "No Ingress resources found"
		return result
	}

	var evidence []models.Evidence
	for _, ing := range ingresses {
		if isSystemNamespace(ing.Namespace) {
			continue
		}
		if len(ing.Spec.TLS) == 0 {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Ingress '%s/%s' has no TLS configuration — serves plaintext HTTP",
					ing.Namespace, ing.Name),
				Resource: models.Resource{Kind: "Ingress", Name: ing.Name, Namespace: ing.Namespace},
				Field:    "spec.tls",
				Value:    "not configured",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All Ingress resources have TLS configured"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d Ingress resource(s) without TLS", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &TLSIngressCheck{}
