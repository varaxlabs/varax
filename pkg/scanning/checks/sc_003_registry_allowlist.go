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

// RegistryAllowlistCheck verifies that all running images come from approved registries.
type RegistryAllowlistCheck struct{}

func (c *RegistryAllowlistCheck) ID() string          { return "SC-003" }
func (c *RegistryAllowlistCheck) Name() string        { return "Registry Allowlist" }
func (c *RegistryAllowlistCheck) Description() string { return "Ensure all container images come from approved registries" }
func (c *RegistryAllowlistCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *RegistryAllowlistCheck) Benchmark() string         { return BenchmarkSupplyChain }
func (c *RegistryAllowlistCheck) Section() string           { return "3" }

// defaultAllowedRegistries is the default set of approved registries.
var defaultAllowedRegistries = []string{
	"gcr.io",
	"ghcr.io",
	"docker.io",
	"registry.k8s.io",
	"quay.io",
}

// isAllowedRegistry checks if a registry matches the allowlist.
// Supports exact match and suffix matching for ECR-style registries.
func isAllowedRegistry(registry string) bool {
	for _, allowed := range defaultAllowedRegistries {
		if registry == allowed {
			return true
		}
	}
	// Allow ECR registries (*.ecr.*.amazonaws.com)
	if strings.HasSuffix(registry, ".amazonaws.com") && strings.Contains(registry, ".ecr.") {
		return true
	}
	return false
}

func (c *RegistryAllowlistCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		registry, _, _ := parseImageRef(container.Image)
		if isAllowedRegistry(registry) {
			return nil
		}
		return &models.Evidence{
			Message: fmt.Sprintf("Container '%s' in pod '%s/%s' uses image from non-approved registry '%s'",
				container.Name, pod.Namespace, pod.Name, registry),
			Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
			Field:    fmt.Sprintf("spec.containers[%s].image", container.Name),
			Value:    registry,
		}
	})
}

var _ scanning.Check = &RegistryAllowlistCheck{}
