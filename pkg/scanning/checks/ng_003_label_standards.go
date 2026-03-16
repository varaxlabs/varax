package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// LabelStandardsCheck verifies that Deployments have required organizational labels.
type LabelStandardsCheck struct{}

func (c *LabelStandardsCheck) ID() string          { return "NG-003" }
func (c *LabelStandardsCheck) Name() string        { return "Label Standards" }
func (c *LabelStandardsCheck) Description() string { return "Ensure resources have required organizational labels for ownership and traceability" }
func (c *LabelStandardsCheck) Severity() models.Severity { return models.SeverityLow }
func (c *LabelStandardsCheck) Benchmark() string         { return BenchmarkNamespaceGov }
func (c *LabelStandardsCheck) Section() string           { return "3" }

// defaultRequiredLabels are the Kubernetes recommended labels for identification.
var defaultRequiredLabels = []string{
	"app.kubernetes.io/name",
	"app.kubernetes.io/component",
	"app.kubernetes.io/managed-by",
}

func (c *LabelStandardsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	deployments, err := scanning.ListDeployments(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list deployments"
		return result
	}

	var evidence []models.Evidence
	for _, deploy := range deployments {
		if isSystemNamespace(deploy.Namespace) {
			continue
		}
		var missing []string
		for _, label := range defaultRequiredLabels {
			if _, ok := deploy.Labels[label]; !ok {
				missing = append(missing, label)
			}
		}
		if len(missing) > 0 {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Deployment '%s/%s' is missing required labels: %v",
					deploy.Namespace, deploy.Name, missing),
				Resource: models.Resource{Kind: "Deployment", Name: deploy.Name, Namespace: deploy.Namespace},
				Field:    "metadata.labels",
				Value:    fmt.Sprintf("missing: %v", missing),
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All Deployments have required labels"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d Deployment(s) missing required labels", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &LabelStandardsCheck{}
