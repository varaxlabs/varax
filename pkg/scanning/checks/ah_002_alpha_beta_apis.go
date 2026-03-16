package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// AlphaBetaAPICheck flags resources using alpha or beta API versions.
type AlphaBetaAPICheck struct{}

func (c *AlphaBetaAPICheck) ID() string          { return "AH-002" }
func (c *AlphaBetaAPICheck) Name() string        { return "Alpha/Beta API Usage" }
func (c *AlphaBetaAPICheck) Description() string { return "Flag resources using unstable alpha or beta API versions" }
func (c *AlphaBetaAPICheck) Severity() models.Severity { return models.SeverityLow }
func (c *AlphaBetaAPICheck) Benchmark() string         { return BenchmarkAPIHygiene }
func (c *AlphaBetaAPICheck) Section() string           { return "2" }

func (c *AlphaBetaAPICheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	_, apiResourceLists, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		if apiResourceLists == nil {
			result.Status = models.StatusSkip
			result.Message = fmt.Sprintf("failed to discover server APIs: %v", err)
			return result
		}
	}

	var evidence []models.Evidence
	for _, resourceList := range apiResourceLists {
		gv := resourceList.GroupVersion

		// Extract version part from group/version
		parts := strings.Split(gv, "/")
		version := parts[len(parts)-1]

		if !strings.Contains(version, "alpha") && !strings.Contains(version, "beta") {
			continue
		}

		// Skip deprecated APIs already covered by AH-001
		if _, isDeprecated := deprecatedAPIs[gv]; isDeprecated {
			continue
		}

		// Count non-subresources
		resourceNames := make([]string, 0, len(resourceList.APIResources))
		for _, r := range resourceList.APIResources {
			if !strings.Contains(r.Name, "/") {
				resourceNames = append(resourceNames, r.Name)
			}
		}

		if len(resourceNames) > 0 {
			stability := "beta"
			if strings.Contains(version, "alpha") {
				stability = "alpha"
			}
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Unstable %s API '%s' is served with %d resource type(s)",
					stability, gv, len(resourceNames)),
				Resource: models.Resource{Kind: "APIService", Name: gv},
				Field:    "groupVersion",
				Value:    fmt.Sprintf("stability: %s, resources: %v", stability, resourceNames),
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No unstable API versions detected"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d unstable API version(s) in use", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &AlphaBetaAPICheck{}
