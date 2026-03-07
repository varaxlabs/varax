package remediators

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	"k8s.io/client-go/kubernetes"
)

// containerSecurityContextPatch builds a strategic merge patch for a container's securityContext field.
func containerSecurityContextPatch(owner *remediation.WorkloadOwner, containerName string, scPatch map[string]any) ([]byte, error) {
	container := map[string]any{
		"name":            containerName,
		"securityContext": scPatch,
	}

	var patch map[string]any
	switch owner.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		patch = map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"containers": []any{container},
					},
				},
			},
		}
	case "Pod":
		patch = map[string]any{
			"spec": map[string]any{
				"containers": []any{container},
			},
		}
	default:
		return nil, fmt.Errorf("unsupported owner kind: %s", owner.Kind)
	}

	return json.Marshal(patch)
}

// PrivilegeEscalationRemediator sets allowPrivilegeEscalation: false.
type PrivilegeEscalationRemediator struct{}

func (r *PrivilegeEscalationRemediator) CheckID() string { return "CIS-5.2.1" }

func (r *PrivilegeEscalationRemediator) Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	return planSecurityContextPatch(ctx, client, evidence, "CIS-5.2.1",
		"securityContext.allowPrivilegeEscalation", "true or unset", "false",
		map[string]any{"allowPrivilegeEscalation": false})
}

// RunAsNonRootRemediator sets runAsNonRoot: true.
type RunAsNonRootRemediator struct{}

func (r *RunAsNonRootRemediator) CheckID() string { return "CIS-5.2.2" }

func (r *RunAsNonRootRemediator) Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	return planSecurityContextPatch(ctx, client, evidence, "CIS-5.2.2",
		"securityContext.runAsNonRoot", "false or unset", "true",
		map[string]any{"runAsNonRoot": true})
}

// PrivilegedRemediator sets privileged: false.
type PrivilegedRemediator struct{}

func (r *PrivilegedRemediator) CheckID() string { return "CIS-5.2.3" }

func (r *PrivilegedRemediator) Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	return planSecurityContextPatch(ctx, client, evidence, "CIS-5.2.3",
		"securityContext.privileged", "true", "false",
		map[string]any{"privileged": false})
}

// DropCapabilitiesRemediator adds capabilities.drop: ["ALL"].
type DropCapabilitiesRemediator struct{}

func (r *DropCapabilitiesRemediator) CheckID() string { return "CIS-5.2.4" }

func (r *DropCapabilitiesRemediator) Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	return planSecurityContextPatch(ctx, client, evidence, "CIS-5.2.4",
		"securityContext.capabilities.drop", "missing ALL", `["ALL"]`,
		map[string]any{"capabilities": map[string]any{"drop": []string{"ALL"}}})
}

// SeccompRemediator sets seccompProfile.type: RuntimeDefault at the pod level.
type SeccompRemediator struct{}

func (r *SeccompRemediator) CheckID() string { return "CIS-5.7.2" }

func (r *SeccompRemediator) Plan(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence) ([]remediation.RemediationAction, error) {
	owners := resolveUniqueOwners(ctx, client, evidence)
	var actions []remediation.RemediationAction

	for _, owner := range owners {
		patchData, err := podSecurityContextPatch(owner, map[string]any{
			"seccompProfile": map[string]any{"type": "RuntimeDefault"},
		})
		if err != nil {
			continue
		}

		actions = append(actions, remediation.RemediationAction{
			CheckID:    "CIS-5.7.2",
			ActionType: remediation.ActionPatch,
			TargetKind: owner.Kind,
			TargetName: owner.Name,
			TargetNS:   owner.Namespace,
			Field:      "spec.securityContext.seccompProfile",
			OldValue:   "not set",
			NewValue:   "RuntimeDefault",
			PatchJSON:  patchData,
		})
	}

	return actions, nil
}

// podSecurityContextPatch builds a patch for the pod-level securityContext.
func podSecurityContextPatch(owner *remediation.WorkloadOwner, scPatch map[string]any) ([]byte, error) {
	var patch map[string]any
	switch owner.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		patch = map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"securityContext": scPatch,
					},
				},
			},
		}
	case "Pod":
		patch = map[string]any{
			"spec": map[string]any{
				"securityContext": scPatch,
			},
		}
	default:
		return nil, fmt.Errorf("unsupported owner kind: %s", owner.Kind)
	}
	return json.Marshal(patch)
}

// planSecurityContextPatch is the common implementation for container-level security context remediators.
func planSecurityContextPatch(ctx context.Context, client kubernetes.Interface, evidence []models.Evidence, checkID, field, oldValue, newValue string, scPatch map[string]any) ([]remediation.RemediationAction, error) {
	owners := resolveUniqueOwners(ctx, client, evidence)
	var actions []remediation.RemediationAction

	for _, owner := range owners {
		containerNames := containerNamesFromEvidence(evidence, owner)
		for _, cName := range containerNames {
			patchData, err := containerSecurityContextPatch(owner, cName, scPatch)
			if err != nil {
				continue
			}

			actions = append(actions, remediation.RemediationAction{
				CheckID:    checkID,
				ActionType: remediation.ActionPatch,
				TargetKind: owner.Kind,
				TargetName: owner.Name,
				TargetNS:   owner.Namespace,
				Field:      field,
				OldValue:   oldValue,
				NewValue:   newValue,
				PatchJSON:  patchData,
			})
		}
	}

	return actions, nil
}

var (
	_ remediation.Remediator = &PrivilegeEscalationRemediator{}
	_ remediation.Remediator = &RunAsNonRootRemediator{}
	_ remediation.Remediator = &PrivilegedRemediator{}
	_ remediation.Remediator = &DropCapabilitiesRemediator{}
	_ remediation.Remediator = &SeccompRemediator{}
)
