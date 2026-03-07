package remediators

import (
	"context"
	"encoding/json"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	"k8s.io/client-go/kubernetes"
)

// SATokenRemediator sets automountServiceAccountToken: false on ServiceAccounts.
type SATokenRemediator struct{}

func (r *SATokenRemediator) CheckID() string { return "CIS-5.1.6" }

func (r *SATokenRemediator) Plan(_ context.Context, _ kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	seen := make(map[string]bool)
	var actions []remediation.RemediationAction

	for _, ev := range evidence {
		if ev.Resource.Kind != "ServiceAccount" {
			continue
		}
		key := ev.Resource.Namespace + "/" + ev.Resource.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		patch, _ := json.Marshal(map[string]any{
			"automountServiceAccountToken": false,
		})

		actions = append(actions, remediation.RemediationAction{
			CheckID:    "CIS-5.1.6",
			ActionType: remediation.ActionPatch,
			TargetKind: "ServiceAccount",
			TargetName: ev.Resource.Name,
			TargetNS:   ev.Resource.Namespace,
			Field:      "automountServiceAccountToken",
			OldValue:   "true or unset",
			NewValue:   "false",
			PatchJSON:  patch,
		})
	}

	return actions, nil
}

var _ remediation.Remediator = &SATokenRemediator{}
