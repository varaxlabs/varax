package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

type NSAImagePullPolicyCheck struct{}

func (c *NSAImagePullPolicyCheck) ID() string          { return "NSA-VM-1" }
func (c *NSAImagePullPolicyCheck) Name() string        { return "ImagePullPolicy is Always" }
func (c *NSAImagePullPolicyCheck) Description() string { return "Ensure ImagePullPolicy is Always to prevent running unscanned images" }
func (c *NSAImagePullPolicyCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *NSAImagePullPolicyCheck) Benchmark() string         { return "NSA-CISA" }
func (c *NSAImagePullPolicyCheck) Section() string            { return "VM-1" }

func (c *NSAImagePullPolicyCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
			if container.ImagePullPolicy != corev1.PullAlways {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' has ImagePullPolicy=%s",
						container.Name, pod.Namespace, pod.Name, container.ImagePullPolicy),
					Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
					Field:    fmt.Sprintf("spec.containers[%s].imagePullPolicy", container.Name),
					Value:    string(container.ImagePullPolicy),
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All containers have ImagePullPolicy=Always"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) without ImagePullPolicy=Always", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &NSAImagePullPolicyCheck{}
