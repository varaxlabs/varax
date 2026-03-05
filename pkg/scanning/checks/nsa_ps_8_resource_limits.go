package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type NSAResourceLimitsCheck struct{}

func (c *NSAResourceLimitsCheck) ID() string          { return "NSA-PS-8" }
func (c *NSAResourceLimitsCheck) Name() string        { return "Set CPU/memory resource limits" }
func (c *NSAResourceLimitsCheck) Description() string { return "Ensure all containers have CPU and memory limits set" }
func (c *NSAResourceLimitsCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *NSAResourceLimitsCheck) Benchmark() string         { return "NSA-CISA" }
func (c *NSAResourceLimitsCheck) Section() string            { return "PS-8" }

func (c *NSAResourceLimitsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	pods, err := scanning.ListPods(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list pods"
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range allContainers(pod) {
			limits := container.Resources.Limits
			hasCPU := limits != nil && !limits.Cpu().IsZero()
			hasMem := limits != nil && !limits.Memory().IsZero()
			if !hasCPU || !hasMem {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' missing resource limits",
						container.Name, pod.Namespace, pod.Name),
					Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
					Field:    fmt.Sprintf("spec.containers[%s].resources.limits", container.Name),
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All containers have CPU and memory limits"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) without resource limits", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &NSAResourceLimitsCheck{}
