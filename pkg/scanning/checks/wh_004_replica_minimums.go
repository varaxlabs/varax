package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// ReplicaMinimumsCheck flags Deployments and StatefulSets with only a single replica.
type ReplicaMinimumsCheck struct{}

func (c *ReplicaMinimumsCheck) ID() string          { return "WH-004" }
func (c *ReplicaMinimumsCheck) Name() string        { return "Replica Minimums" }
func (c *ReplicaMinimumsCheck) Description() string { return "Flag single-replica workloads that lack high availability" }
func (c *ReplicaMinimumsCheck) Severity() models.Severity { return models.SeverityLow }
func (c *ReplicaMinimumsCheck) Benchmark() string         { return BenchmarkWorkloadHygiene }
func (c *ReplicaMinimumsCheck) Section() string           { return "4" }

const singleReplicaExemptAnnotation = "varax.io/single-replica-ok"

func (c *ReplicaMinimumsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	deployments, err := scanning.ListDeployments(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list deployments"
		return result
	}

	statefulSets, err := scanning.ListStatefulSets(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "failed to list statefulsets"
		return result
	}

	var evidence []models.Evidence

	for _, deploy := range deployments {
		if isSystemNamespace(deploy.Namespace) {
			continue
		}
		if deploy.Annotations[singleReplicaExemptAnnotation] == "true" {
			continue
		}
		replicas := int32(1)
		if deploy.Spec.Replicas != nil {
			replicas = *deploy.Spec.Replicas
		}
		if replicas <= 1 {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Deployment '%s/%s' has only %d replica(s)",
					deploy.Namespace, deploy.Name, replicas),
				Resource: models.Resource{Kind: "Deployment", Name: deploy.Name, Namespace: deploy.Namespace},
				Field:    "spec.replicas",
				Value:    fmt.Sprintf("%d", replicas),
			})
		}
	}

	for _, sts := range statefulSets {
		if isSystemNamespace(sts.Namespace) {
			continue
		}
		if sts.Annotations[singleReplicaExemptAnnotation] == "true" {
			continue
		}
		replicas := int32(1)
		if sts.Spec.Replicas != nil {
			replicas = *sts.Spec.Replicas
		}
		if replicas <= 1 {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("StatefulSet '%s/%s' has only %d replica(s)",
					sts.Namespace, sts.Name, replicas),
				Resource: models.Resource{Kind: "StatefulSet", Name: sts.Name, Namespace: sts.Namespace},
				Field:    "spec.replicas",
				Value:    fmt.Sprintf("%d", replicas),
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "All workloads have multiple replicas or are exempt"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d single-replica workload(s)", len(evidence))
		result.Evidence = evidence
	}
	return result
}

var _ scanning.Check = &ReplicaMinimumsCheck{}
