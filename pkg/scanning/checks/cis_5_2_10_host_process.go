package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
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
	return runContainerCheck(ctx, client, c, func(container corev1.Container, pod corev1.Pod) *models.Evidence {
		if container.SecurityContext != nil &&
			container.SecurityContext.WindowsOptions != nil &&
			container.SecurityContext.WindowsOptions.HostProcess != nil &&
			*container.SecurityContext.WindowsOptions.HostProcess {
			return &models.Evidence{
				Message:  fmt.Sprintf("Container '%s' in pod '%s/%s' uses HostProcess", container.Name, pod.Namespace, pod.Name),
				Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
				Field:    fmt.Sprintf("spec.containers[%s].securityContext.windowsOptions.hostProcess", container.Name),
				Value:    "true",
			}
		}
		return nil
	})
}

var _ scanning.Check = &HostProcessCheck{}
