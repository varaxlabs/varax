package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// PDBCoverageCheck verifies that multi-replica workloads have PodDisruptionBudgets.
type PDBCoverageCheck struct{}

func (c *PDBCoverageCheck) ID() string          { return "WH-005" }
func (c *PDBCoverageCheck) Name() string        { return "PDB Coverage" }
func (c *PDBCoverageCheck) Description() string { return "Ensure multi-replica workloads have PodDisruptionBudgets for controlled maintenance" }
func (c *PDBCoverageCheck) Severity() models.Severity { return models.SeverityLow }
func (c *PDBCoverageCheck) Benchmark() string         { return BenchmarkWorkloadHygiene }
func (c *PDBCoverageCheck) Section() string           { return "5" }

func (c *PDBCoverageCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	deployments, err := scanning.ListDeployments(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list deployments"
		return result
	}

	pdbs, err := scanning.ListPDBs(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list PDBs"
		return result
	}

	statefulSets, err := scanning.ListStatefulSets(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list statefulsets"
		return result
	}

	// Index PDBs by namespace for efficient lookup
	pdbsByNS := make(map[string][]policyv1.PodDisruptionBudget)
	for _, pdb := range pdbs {
		pdbsByNS[pdb.Namespace] = append(pdbsByNS[pdb.Namespace], pdb)
	}

	var evidence []models.Evidence

	for _, deploy := range deployments {
		if isSystemNamespace(deploy.Namespace) {
			continue
		}
		replicas := int32(1)
		if deploy.Spec.Replicas != nil {
			replicas = *deploy.Spec.Replicas
		}
		if replicas <= 1 {
			continue
		}

		if !hasPDBForLabels(pdbsByNS[deploy.Namespace], deploy.Spec.Selector) {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Deployment '%s/%s' (%d replicas) has no matching PodDisruptionBudget",
					deploy.Namespace, deploy.Name, replicas),
				Resource: models.Resource{Kind: "Deployment", Name: deploy.Name, Namespace: deploy.Namespace},
				Field:    "PodDisruptionBudget",
				Value:    "not found",
			})
		}
	}

	for _, sts := range statefulSets {
		if isSystemNamespace(sts.Namespace) {
			continue
		}
		replicas := int32(1)
		if sts.Spec.Replicas != nil {
			replicas = *sts.Spec.Replicas
		}
		if replicas <= 1 {
			continue
		}

		if !hasPDBForLabels(pdbsByNS[sts.Namespace], sts.Spec.Selector) {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("StatefulSet '%s/%s' (%d replicas) has no matching PodDisruptionBudget",
					sts.Namespace, sts.Name, replicas),
				Resource: models.Resource{Kind: "StatefulSet", Name: sts.Name, Namespace: sts.Namespace},
				Field:    "PodDisruptionBudget",
				Value:    "not found",
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All multi-replica workloads have PDBs or no HA workloads found"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d multi-replica workload(s) without PDBs", len(evidence))
		result.Evidence = evidence
	}
	return result
}

// hasPDBForLabels checks if any PDB has a selector that matches the workload's labels.
func hasPDBForLabels(pdbs []policyv1.PodDisruptionBudget, selector *metav1.LabelSelector) bool {
	if selector == nil {
		return false
	}
	workloadLabels := selector.MatchLabels
	for _, pdb := range pdbs {
		if pdb.Spec.Selector == nil {
			continue
		}
		pdbSelector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		if pdbSelector.Matches(labels.Set(workloadLabels)) {
			return true
		}
	}
	return false
}

var _ scanning.Check = &PDBCoverageCheck{}
