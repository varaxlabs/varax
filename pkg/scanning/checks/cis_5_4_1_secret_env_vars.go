package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// SecretEnvVarCheck verifies that secrets are not referenced via environment variables.
type SecretEnvVarCheck struct{}

func (c *SecretEnvVarCheck) ID() string      { return "CIS-5.4.1" }
func (c *SecretEnvVarCheck) Name() string     { return "Prefer using Secrets as files over Secrets as environment variables" }
func (c *SecretEnvVarCheck) Description() string {
	return "Ensure that secrets are mounted as files rather than exposed as environment variables"
}
func (c *SecretEnvVarCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *SecretEnvVarCheck) Benchmark() string         { return "CIS" }
func (c *SecretEnvVarCheck) Section() string            { return "5.4.1" }

func (c *SecretEnvVarCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := models.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Description: c.Description(),
		Benchmark:   c.Benchmark(),
		Section:     c.Section(),
		Severity:    c.Severity(),
	}

	pods, err := scanning.ListPods(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list Pods"
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		containers := allContainers(pod)
		for _, container := range containers {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					evidence = append(evidence, models.Evidence{
						Message: fmt.Sprintf("Container '%s' in pod '%s/%s' references secret '%s' via env var '%s'",
							container.Name, pod.Namespace, pod.Name, env.ValueFrom.SecretKeyRef.Name, env.Name),
						Resource: models.Resource{
							Kind:      "Pod",
							Name:      pod.Name,
							Namespace: pod.Namespace,
						},
						Field: fmt.Sprintf("spec.containers[%s].env[%s].valueFrom.secretKeyRef", container.Name, env.Name),
						Value: env.ValueFrom.SecretKeyRef.Name,
					})
				}
			}
			for _, envFrom := range container.EnvFrom {
				if envFrom.SecretRef != nil {
					evidence = append(evidence, models.Evidence{
						Message: fmt.Sprintf("Container '%s' in pod '%s/%s' loads secret '%s' via envFrom",
							container.Name, pod.Namespace, pod.Name, envFrom.SecretRef.Name),
						Resource: models.Resource{
							Kind:      "Pod",
							Name:      pod.Name,
							Namespace: pod.Namespace,
						},
						Field: fmt.Sprintf("spec.containers[%s].envFrom[].secretRef", container.Name),
						Value: envFrom.SecretRef.Name,
					})
				}
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No containers reference secrets via environment variables"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) referencing secrets via env vars", len(evidence))
		result.Evidence = evidence
	}

	return result
}

var _ scanning.Check = &SecretEnvVarCheck{}
