package remediators

import (
	"context"
	"encoding/json"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	"k8s.io/client-go/kubernetes"
)

// NetworkPolicyRemediator creates a default-deny NetworkPolicy in namespaces without one.
type NetworkPolicyRemediator struct{}

func (r *NetworkPolicyRemediator) CheckID() string { return "CIS-5.3.2" }

func (r *NetworkPolicyRemediator) Plan(_ context.Context, _ kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
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
			Name:      "varax-default-deny",
			Namespace: ns,
		})

		actions = append(actions, remediation.RemediationAction{
			CheckID:    "CIS-5.3.2",
			ActionType: remediation.ActionCreate,
			TargetKind: "NetworkPolicy",
			TargetName: "varax-default-deny",
			TargetNS:   ns,
			Field:      "networkPolicies",
			OldValue:   "0",
			NewValue:   "default-deny ingress+egress",
			PatchJSON:  spec,
		})
	}

	return actions, nil
}

var _ remediation.Remediator = &NetworkPolicyRemediator{}
