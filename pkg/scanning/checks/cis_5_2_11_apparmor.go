package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type AppArmorCheck struct{}

func (c *AppArmorCheck) ID() string          { return "CIS-5.2.11" }
func (c *AppArmorCheck) Name() string        { return "Restrict AppArmor profiles" }
func (c *AppArmorCheck) Description() string { return "Ensure pods use an AppArmor profile where applicable" }
func (c *AppArmorCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *AppArmorCheck) Benchmark() string         { return "CIS" }
func (c *AppArmorCheck) Section() string            { return "5.2.11" }

func (c *AppArmorCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
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
		for _, container := range pod.Spec.Containers {
			annotKey := "container.apparmor.security.beta.kubernetes.io/" + container.Name
			val, ok := pod.Annotations[annotKey]
			if ok && val == "unconfined" {
				evidence = append(evidence, models.Evidence{
					Message: fmt.Sprintf("Container '%s' in pod '%s/%s' has unconfined AppArmor profile",
						container.Name, pod.Namespace, pod.Name),
					Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
					Field:    fmt.Sprintf("annotations[%s]", annotKey),
					Value:    val,
				})
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No containers with unconfined AppArmor profiles"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d container(s) with unconfined AppArmor", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &AppArmorCheck{}
