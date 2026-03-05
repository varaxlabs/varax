package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

type ProcMountCheck struct{}

func (c *ProcMountCheck) ID() string          { return "CIS-5.2.9" }
func (c *ProcMountCheck) Name() string        { return "Minimize the admission of containers with /proc mount type" }
func (c *ProcMountCheck) Description() string { return "Ensure containers do not use Unmasked proc mount" }
func (c *ProcMountCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *ProcMountCheck) Benchmark() string         { return "CIS" }
func (c *ProcMountCheck) Section() string            { return "5.2.9" }

func (c *ProcMountCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			if container.SecurityContext != nil && container.SecurityContext.ProcMount != nil {
				pm := *container.SecurityContext.ProcMount
				if pm == corev1.UnmaskedProcMount {
					evidence = append(evidence, models.Evidence{
						Message: fmt.Sprintf("Container '%s' in pod '%s/%s' uses Unmasked proc mount",
							container.Name, pod.Namespace, pod.Name),
						Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
						Field:    fmt.Sprintf("spec.containers[%s].securityContext.procMount", container.Name),
						Value:    "Unmasked",
					})
				}
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No containers with Unmasked proc mount"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) with Unmasked proc mount", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &ProcMountCheck{}
