package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// SBOMAttestationCheck verifies that running container images have SBOM
// attestation annotations present on their pods.
type SBOMAttestationCheck struct{}

func (c *SBOMAttestationCheck) ID() string          { return "SC-001" }
func (c *SBOMAttestationCheck) Name() string        { return "SBOM Attestation Presence" }
func (c *SBOMAttestationCheck) Description() string { return "Check whether running images have SBOM attestation annotations" }
func (c *SBOMAttestationCheck) Severity() models.Severity { return models.SeverityLow }
func (c *SBOMAttestationCheck) Benchmark() string         { return BenchmarkSupplyChain }
func (c *SBOMAttestationCheck) Section() string           { return "1" }

// sbomAnnotations are well-known annotations that indicate SBOM presence.
var sbomAnnotations = []string{
	"org.opencontainers.image.sbom",
	"io.syft.sbom",
	"in-toto.io/attestation",
	"dev.cosignproject.cosign/sbom",
}

func (c *SBOMAttestationCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runPodSpecCheck(ctx, client, c, func(pod corev1.Pod) *models.Evidence {
		for _, key := range sbomAnnotations {
			if _, ok := pod.Annotations[key]; ok {
				return nil
			}
		}
		return &models.Evidence{
			Message: fmt.Sprintf("Pod '%s/%s' has no SBOM attestation annotations",
				pod.Namespace, pod.Name),
			Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
			Field:    "metadata.annotations",
			Value:    "no SBOM attestation found",
		}
	})
}

var _ scanning.Check = &SBOMAttestationCheck{}
