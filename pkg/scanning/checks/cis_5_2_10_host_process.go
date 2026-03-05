package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type HostProcessCheck struct{}

func (c *HostProcessCheck) ID() string          { return "CIS-5.2.10" }
func (c *HostProcessCheck) Name() string        { return "Minimize use of host process containers" }
func (c *HostProcessCheck) Description() string { return "Ensure containers do not use Windows HostProcess" }
func (c *HostProcessCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *HostProcessCheck) Benchmark() string         { return "CIS" }
func (c *HostProcessCheck) Section() string            { return "5.2.10" }

func (c *HostProcessCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			if container.SecurityContext != nil &&
				container.SecurityContext.WindowsOptions != nil &&
				container.SecurityContext.WindowsOptions.HostProcess != nil &&
				*container.SecurityContext.WindowsOptions.HostProcess {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' uses HostProcess",
						container.Name, pod.Namespace, pod.Name),
					Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
					Field:    fmt.Sprintf("spec.containers[%s].securityContext.windowsOptions.hostProcess", container.Name),
					Value:    "true",
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No host process containers found"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d host process container(s)", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &HostProcessCheck{}
