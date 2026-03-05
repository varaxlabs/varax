package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type NSAImmutableFSCheck struct{}

func (c *NSAImmutableFSCheck) ID() string          { return "NSA-PS-7" }
func (c *NSAImmutableFSCheck) Name() string        { return "Use immutable root filesystem" }
func (c *NSAImmutableFSCheck) Description() string { return "Ensure readOnlyRootFilesystem is true on all containers" }
func (c *NSAImmutableFSCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *NSAImmutableFSCheck) Benchmark() string         { return "NSA-CISA" }
func (c *NSAImmutableFSCheck) Section() string            { return "PS-7" }

func (c *NSAImmutableFSCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			readOnly := false
			if container.SecurityContext != nil && container.SecurityContext.ReadOnlyRootFilesystem != nil {
				readOnly = *container.SecurityContext.ReadOnlyRootFilesystem
			}
			if !readOnly {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' does not have readOnlyRootFilesystem",
						container.Name, pod.Namespace, pod.Name),
					Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
					Field:    fmt.Sprintf("spec.containers[%s].securityContext.readOnlyRootFilesystem", container.Name),
					Value:    "false",
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All containers have readOnlyRootFilesystem"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) without readOnlyRootFilesystem", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &NSAImmutableFSCheck{}
