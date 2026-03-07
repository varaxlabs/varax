package remediators

import (
	"context"
	"encoding/json"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	"k8s.io/client-go/kubernetes"
)

// LimitRangeRemediator creates a default LimitRange in namespaces without one.
type LimitRangeRemediator struct{}

func (r *LimitRangeRemediator) CheckID() string { return "CIS-5.7.1" }

func (r *LimitRangeRemediator) Plan(_ context.Context, _ kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	seen := make(map[string]bool)
	var actions []remediation.RemediationAction

	for _, ev := range evidence {
		if ev.Resource.Kind != "Namespace" {
			continue
		}
		ns := ev.Resource.Name
		if seen[ns] {
			continue
		}
		seen[ns] = true

		spec, _ := json.Marshal(struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		}{
			Name:      "varax-default-limits",
			Namespace: ns,
		})

		actions = append(actions, remediation.RemediationAction{
			CheckID:    "CIS-5.7.1",
			ActionType: remediation.ActionCreate,
			TargetKind: "LimitRange",
			TargetName: "varax-default-limits",
			TargetNS:   ns,
			Field:      "limitRanges",
			OldValue:   "0",
			NewValue:   "default CPU/memory limits",
			PatchJSON:  spec,
		})
	}

	return actions, nil
}

var _ remediation.Remediator = &LimitRangeRemediator{}
