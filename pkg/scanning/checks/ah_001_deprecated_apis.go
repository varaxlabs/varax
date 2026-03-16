package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// DeprecatedAPICheck flags resources using deprecated Kubernetes API versions.
type DeprecatedAPICheck struct{}

func (c *DeprecatedAPICheck) ID() string          { return "AH-001" }
func (c *DeprecatedAPICheck) Name() string        { return "Deprecated API Usage" }
func (c *DeprecatedAPICheck) Description() string { return "Flag resources using deprecated Kubernetes API versions" }
func (c *DeprecatedAPICheck) Severity() models.Severity { return models.SeverityMedium }
func (c *DeprecatedAPICheck) Benchmark() string         { return BenchmarkAPIHygiene }
func (c *DeprecatedAPICheck) Section() string           { return "1" }

// deprecationInfo tracks when an API was deprecated and what replaced it.
type deprecationInfo struct {
	Deprecated  string // K8s version when deprecated
	Removed     string // K8s version when removed
	Replacement string // What to use instead
}

// deprecatedAPIs maps group/version to deprecation information.
var deprecatedAPIs = map[string]deprecationInfo{
	"extensions/v1beta1": {
		Deprecated: "1.14", Removed: "1.22",
		Replacement: "networking.k8s.io/v1 (Ingress), apps/v1 (Deployment, etc.)",
	},
	"networking.k8s.io/v1beta1": {
		Deprecated: "1.19", Removed: "1.22",
		Replacement: "networking.k8s.io/v1",
	},
	"policy/v1beta1": {
		Deprecated: "1.21", Removed: "1.25",
		Replacement: "policy/v1 (PDB), Pod Security Standards (PSP)",
	},
	"flowcontrol.apiserver.k8s.io/v1beta1": {
		Deprecated: "1.23", Removed: "1.26",
		Replacement: "flowcontrol.apiserver.k8s.io/v1",
	},
	"flowcontrol.apiserver.k8s.io/v1beta2": {
		Deprecated: "1.26", Removed: "1.29",
		Replacement: "flowcontrol.apiserver.k8s.io/v1",
	},
	"autoscaling/v2beta1": {
		Deprecated: "1.23", Removed: "1.26",
		Replacement: "autoscaling/v2",
	},
	"batch/v1beta1": {
		Deprecated: "1.21", Removed: "1.25",
		Replacement: "batch/v1",
	},
	"discovery.k8s.io/v1beta1": {
		Deprecated: "1.21", Removed: "1.25",
		Replacement: "discovery.k8s.io/v1",
	},
	"storage.k8s.io/v1beta1": {
		Deprecated: "1.22", Removed: "1.25",
		Replacement: "storage.k8s.io/v1",
	},
}

func (c *DeprecatedAPICheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	// Use discovery to check which API groups the server serves
	_, apiResourceLists, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		// Discovery may return partial results with an error for some groups
		if apiResourceLists == nil {
			result.Status = models.StatusSkip
			result.Message = fmt.Sprintf("failed to discover server APIs: %v", err)
			return result
		}
	}

	var evidence []models.Evidence
	for _, resourceList := range apiResourceLists {
		gv := resourceList.GroupVersion
		info, isDeprecated := deprecatedAPIs[gv]
		if !isDeprecated {
			continue
		}

		// Check if there are any resources under this deprecated API
		resourceNames := make([]string, 0, len(resourceList.APIResources))
		for _, r := range resourceList.APIResources {
			// Skip subresources (contain "/")
			if !strings.Contains(r.Name, "/") {
				resourceNames = append(resourceNames, r.Name)
			}
		}

		if len(resourceNames) > 0 {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Deprecated API '%s' is still served (deprecated in %s, removed in %s). Use %s instead.",
					gv, info.Deprecated, info.Removed, info.Replacement),
				Resource: models.Resource{Kind: "APIService", Name: gv},
				Field:    "groupVersion",
				Value:    fmt.Sprintf("resources: %v", resourceNames),
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No deprecated API versions detected"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d deprecated API version(s) still in use", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &DeprecatedAPICheck{}
