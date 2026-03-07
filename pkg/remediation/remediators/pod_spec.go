package remediators

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	"k8s.io/client-go/kubernetes"
)

func podSpecBoolPatch(owner *remediation.WorkloadOwner, fieldName string) ([]byte, error) {
	specPatch := map[string]any{fieldName: false}

	var patch map[string]any
	switch owner.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		patch = map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"spec": specPatch,
				},
			},
		}
	case "Pod":
		patch = map[string]any{
			"spec": specPatch,
		}
	default:
		return nil, fmt.Errorf("unsupported owner kind: %s", owner.Kind)
	}

	return json.Marshal(patch)
}

func planPodSpecBoolPatch(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence, checkID, k8sField string) ([]remediation.RemediationAction, error) {
	owners := resolveUniqueOwners(ctx, client, evidence)
	var actions []remediation.RemediationAction

	for _, owner := range owners {
		patchData, err := podSpecBoolPatch(owner, k8sField)
		if err != nil {
			continue
		}

		actions = append(actions, remediation.RemediationAction{
			CheckID:    checkID,
			ActionType: remediation.ActionPatch,
			TargetKind: owner.Kind,
			TargetName: owner.Name,
			TargetNS:   owner.Namespace,
			Field:      "spec." + k8sField,
			OldValue:   "true",
			NewValue:   "false",
			PatchJSON:  patchData,
		})
	}

	return actions, nil
}

// HostPIDRemediator sets hostPID: false.
type HostPIDRemediator struct{}

func (r *HostPIDRemediator) CheckID() string { return "CIS-5.2.5" }

func (r *HostPIDRemediator) Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	return planPodSpecBoolPatch(ctx, client, evidence, "CIS-5.2.5", "hostPID")
}

// HostIPCRemediator sets hostIPC: false.
type HostIPCRemediator struct{}

func (r *HostIPCRemediator) CheckID() string { return "CIS-5.2.6" }

func (r *HostIPCRemediator) Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	return planPodSpecBoolPatch(ctx, client, evidence, "CIS-5.2.6", "hostIPC")
}

// HostNetworkRemediator sets hostNetwork: false.
type HostNetworkRemediator struct{}

func (r *HostNetworkRemediator) CheckID() string { return "CIS-5.2.7" }

func (r *HostNetworkRemediator) Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	return planPodSpecBoolPatch(ctx, client, evidence, "CIS-5.2.7", "hostNetwork")
}

var (
	_ remediation.Remediator = &HostPIDRemediator{}
	_ remediation.Remediator = &HostIPCRemediator{}
	_ remediation.Remediator = &HostNetworkRemediator{}
)
