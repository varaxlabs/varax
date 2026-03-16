package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// ImageSignatureCheck verifies that running container images have
// cryptographic signature annotations (Cosign/Sigstore).
type ImageSignatureCheck struct{}

func (c *ImageSignatureCheck) ID() string          { return "SC-002" }
func (c *ImageSignatureCheck) Name() string        { return "Image Signature Presence" }
func (c *ImageSignatureCheck) Description() string { return "Check whether running images have cryptographic signature annotations" }
func (c *ImageSignatureCheck) Severity() models.Severity { return models.SeverityLow }
func (c *ImageSignatureCheck) Benchmark() string         { return BenchmarkSupplyChain }
func (c *ImageSignatureCheck) Section() string           { return "2" }

var signatureAnnotations = []string{
	"dev.cosignproject.cosign/signature",
	"cosign.sigstore.dev/signature",
}

func (c *ImageSignatureCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runPodSpecCheck(ctx, client, c, func(pod corev1.Pod) *models.Evidence {
		for _, key := range signatureAnnotations {
			if _, ok := pod.Annotations[key]; ok {
				return nil
			}
		}
		return &models.Evidence{
			Message: fmt.Sprintf("Pod '%s/%s' has no image signature annotations",
				pod.Namespace, pod.Name),
			Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
			Field:    "metadata.annotations",
			Value:    "no signature found",
		}
	})
}

var _ scanning.Check = &ImageSignatureCheck{}
