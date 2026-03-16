package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// ImageTagPolicyCheck verifies that containers use immutable image references
// (digest or semver) rather than mutable tags like :latest.
type ImageTagPolicyCheck struct{}

func (c *ImageTagPolicyCheck) ID() string          { return "WH-001" }
func (c *ImageTagPolicyCheck) Name() string        { return "Image Tag Policy" }
func (c *ImageTagPolicyCheck) Description() string { return "Ensure containers use immutable image references, not mutable tags like :latest" }
func (c *ImageTagPolicyCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *ImageTagPolicyCheck) Benchmark() string         { return BenchmarkWorkloadHygiene }
func (c *ImageTagPolicyCheck) Section() string           { return "1" }

// mutableTags are tags that can change without notice and break reproducibility.
var mutableTags = map[string]bool{
	"latest":  true,
	"dev":     true,
	"staging": true,
	"master":  true,
	"main":    true,
}

func (c *ImageTagPolicyCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		// Images using digest references are always acceptable
		if strings.Contains(container.Image, "@") {
			return nil
		}

		_, _, tag := parseImageRef(container.Image)

		// parseImageRef normalises empty tags to "latest"
		if mutableTags[tag] {
			return &models.Evidence{
				Message: fmt.Sprintf("Container '%s' in pod '%s/%s' uses mutable image tag '%s'",
					container.Name, pod.Namespace, pod.Name, tag),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    fmt.Sprintf("spec.containers[%s].image", container.Name),
				Value:    container.Image,
			}
		}

		return nil
	})
}

var _ scanning.Check = &ImageTagPolicyCheck{}
