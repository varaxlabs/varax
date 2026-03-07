package remediation

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// stubRemediator returns a fixed list of actions for testing.
type stubRemediator struct {
	id      string
	actions []RemediationAction
}

func (s *stubRemediator) CheckID() string { return s.id }
func (s *stubRemediator) Plan(_ context.Context, _ kubernetes.Interface, _ []models.Evidence) ([]RemediationAction, error) {
	return s.actions, nil
}

func makeTestDeployment(name, namespace string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app"},
					},
				},
			},
		},
	}
}

func TestEngine_PlanFromScanResult(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := NewRemediatorRegistry()
	reg.Register(&stubRemediator{
		id: "CIS-5.2.1",
		actions: []RemediationAction{
			{
				CheckID:    "CIS-5.2.1",
				ActionType: ActionPatch,
				TargetKind: "Deployment",
				TargetName: "web",
				TargetNS:   "default",
				Field:      "spec.template.spec.containers[app].securityContext.allowPrivilegeEscalation",
				OldValue:   "true",
				NewValue:   "false",
				PatchJSON:  []byte(`{}`),
			},
		},
	})

	engine := NewEngine(reg, client, true)
	scanResult := &models.ScanResult{
		ID: "scan-1",
		Results: []models.CheckResult{
			{
				ID:     "CIS-5.2.1",
				Status: models.StatusFail,
				Evidence: []models.Evidence{
					{
						Message:  "allows privilege escalation",
						Resource: models.Resource{Kind: "Pod", Name: "web-abc", Namespace: "default"},
					},
				},
			},
			{
				ID:     "CIS-1.2.1",
				Status: models.StatusPass,
			},
		},
	}

	plan, err := engine.PlanFromScanResult(context.Background(), scanResult)
	require.NoError(t, err)
	assert.Equal(t, "scan-1", plan.ScanID)
	assert.Len(t, plan.Actions, 1)
	assert.Equal(t, "CIS-5.2.1", plan.Actions[0].CheckID)
}

func TestEngine_PlanSkipsSystemNamespaceEvidence(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := NewRemediatorRegistry()
	reg.Register(&stubRemediator{id: "CIS-5.2.1"})

	engine := NewEngine(reg, client, true)
	scanResult := &models.ScanResult{
		ID: "scan-2",
		Results: []models.CheckResult{
			{
				ID:     "CIS-5.2.1",
				Status: models.StatusFail,
				Evidence: []models.Evidence{
					{Resource: models.Resource{Kind: "Pod", Name: "p", Namespace: "kube-system"}},
				},
			},
		},
	}

	plan, err := engine.PlanFromScanResult(context.Background(), scanResult)
	require.NoError(t, err)
	assert.Empty(t, plan.Actions)
}

func TestEngine_ExecuteDryRun(t *testing.T) {
	client := fake.NewSimpleClientset(makeTestDeployment("web", "default"))
	reg := NewRemediatorRegistry()
	engine := NewEngine(reg, client, true)

	plan := &RemediationPlan{
		ScanID: "scan-1",
		DryRun: true,
		Actions: []RemediationAction{
			{
				CheckID:    "CIS-5.2.1",
				ActionType: ActionPatch,
				TargetKind: "Deployment",
				TargetName: "web",
				TargetNS:   "default",
				PatchJSON:  []byte(`{"spec":{"template":{"spec":{"containers":[{"name":"app","securityContext":{"allowPrivilegeEscalation":false}}]}}}}`),
			},
		},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Len(t, report.Results, 1)
	assert.Equal(t, StatusDryRun, report.Results[0].Status)
	assert.Equal(t, 1, report.Summary.DryRunCount)
}

func TestEngine_ExecuteApply(t *testing.T) {
	client := fake.NewSimpleClientset(makeTestDeployment("web", "default"))
	reg := NewRemediatorRegistry()
	engine := NewEngine(reg, client, false)

	plan := &RemediationPlan{
		ScanID: "scan-1",
		DryRun: false,
		Actions: []RemediationAction{
			{
				CheckID:    "CIS-5.2.1",
				ActionType: ActionPatch,
				TargetKind: "Deployment",
				TargetName: "web",
				TargetNS:   "default",
				PatchJSON:  []byte(`{"spec":{"template":{"spec":{"containers":[{"name":"app","securityContext":{"allowPrivilegeEscalation":false}}]}}}}`),
			},
		},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Len(t, report.Results, 1)
	assert.Equal(t, StatusApplied, report.Results[0].Status)
	assert.Equal(t, 1, report.Summary.AppliedCount)
}

func TestEngine_ExecuteSkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := NewRemediatorRegistry()
	engine := NewEngine(reg, client, false)

	plan := &RemediationPlan{
		ScanID: "scan-1",
		DryRun: false,
		Actions: []RemediationAction{
			{
				CheckID:    "CIS-5.2.1",
				ActionType: ActionPatch,
				TargetKind: "Deployment",
				TargetName: "coredns",
				TargetNS:   "kube-system",
				PatchJSON:  []byte(`{}`),
			},
		},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusSkipped, report.Results[0].Status)
	assert.Equal(t, SkipSystemNamespace, report.Results[0].SkipReason)
}

func TestEngine_ExecuteSkipsExclusionLabel(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: "default",
			Labels:    map[string]string{exclusionLabel: "true"},
		},
	})
	reg := NewRemediatorRegistry()
	engine := NewEngine(reg, client, false)

	plan := &RemediationPlan{
		ScanID: "scan-1",
		DryRun: false,
		Actions: []RemediationAction{
			{
				CheckID:    "CIS-5.2.1",
				ActionType: ActionPatch,
				TargetKind: "Deployment",
				TargetName: "web",
				TargetNS:   "default",
				PatchJSON:  []byte(`{}`),
			},
		},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusSkipped, report.Results[0].Status)
	assert.Equal(t, SkipExclusionLabel, report.Results[0].SkipReason)
}

func TestEngine_ExecuteFailure(t *testing.T) {
	client := fake.NewSimpleClientset() // no deployment exists
	reg := NewRemediatorRegistry()
	engine := NewEngine(reg, client, false)

	plan := &RemediationPlan{
		ScanID: "scan-1",
		DryRun: false,
		Actions: []RemediationAction{
			{
				CheckID:    "CIS-5.2.1",
				ActionType: ActionPatch,
				TargetKind: "Deployment",
				TargetName: "nonexistent",
				TargetNS:   "default",
				PatchJSON:  []byte(`{}`),
			},
		},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, report.Results[0].Status)
	assert.NotEmpty(t, report.Results[0].Error)
	assert.Equal(t, 1, report.Summary.FailedCount)
}

func TestEngine_ExecuteProgress(t *testing.T) {
	client := fake.NewSimpleClientset(makeTestDeployment("web", "default"))
	reg := NewRemediatorRegistry()
	engine := NewEngine(reg, client, true)

	plan := &RemediationPlan{
		ScanID: "scan-1",
		DryRun: true,
		Actions: []RemediationAction{
			{
				CheckID:    "CIS-5.2.1",
				ActionType: ActionPatch,
				TargetKind: "Deployment",
				TargetName: "web",
				TargetNS:   "default",
				PatchJSON:  []byte(`{}`),
			},
		},
	}

	var called bool
	progress := func(completed, total int, action RemediationAction) {
		called = true
		assert.Equal(t, 1, completed)
		assert.Equal(t, 1, total)
	}

	_, err := engine.Execute(context.Background(), plan, progress)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestEngine_ExecuteCreateNetworkPolicy(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := NewRemediatorRegistry()
	engine := NewEngine(reg, client, true)

	npJSON, _ := json.Marshal(networkingv1Policy{Name: "default-deny", Namespace: "app"})
	plan := &RemediationPlan{
		ScanID: "scan-1",
		DryRun: true,
		Actions: []RemediationAction{
			{
				CheckID:    "CIS-5.3.2",
				ActionType: ActionCreate,
				TargetKind: "NetworkPolicy",
				TargetName: "default-deny",
				TargetNS:   "app",
				PatchJSON:  npJSON,
			},
		},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusDryRun, report.Results[0].Status)
}

func TestEngine_ExecutePatchStatefulSet(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "data"},
	})
	engine := NewEngine(NewRemediatorRegistry(), client, false)

	plan := &RemediationPlan{
		DryRun: false,
		Actions: []RemediationAction{{
			ActionType: ActionPatch,
			TargetKind: "StatefulSet",
			TargetName: "db",
			TargetNS:   "data",
			PatchJSON:  []byte(`{"spec":{"template":{"spec":{"hostPID":false}}}}`),
		}},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusApplied, report.Results[0].Status)
}

func TestEngine_ExecutePatchDaemonSet(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "monitoring"},
	})
	engine := NewEngine(NewRemediatorRegistry(), client, false)

	plan := &RemediationPlan{
		DryRun: false,
		Actions: []RemediationAction{{
			ActionType: ActionPatch,
			TargetKind: "DaemonSet",
			TargetName: "agent",
			TargetNS:   "monitoring",
			PatchJSON:  []byte(`{"spec":{"template":{"spec":{"hostNetwork":false}}}}`),
		}},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusApplied, report.Results[0].Status)
}

func TestEngine_ExecutePatchPod(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "default"},
	})
	engine := NewEngine(NewRemediatorRegistry(), client, false)

	plan := &RemediationPlan{
		DryRun: false,
		Actions: []RemediationAction{{
			ActionType: ActionPatch,
			TargetKind: "Pod",
			TargetName: "bare",
			TargetNS:   "default",
			PatchJSON:  []byte(`{"spec":{"hostPID":false}}`),
		}},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusApplied, report.Results[0].Status)
}

func TestEngine_ExecutePatchServiceAccount(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "app"},
	})
	engine := NewEngine(NewRemediatorRegistry(), client, false)

	plan := &RemediationPlan{
		DryRun: false,
		Actions: []RemediationAction{{
			ActionType: ActionPatch,
			TargetKind: "ServiceAccount",
			TargetName: "default",
			TargetNS:   "app",
			PatchJSON:  []byte(`{"automountServiceAccountToken":false}`),
		}},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusApplied, report.Results[0].Status)
}

func TestEngine_ExecuteCreateLimitRange(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := NewRemediatorRegistry()
	engine := NewEngine(reg, client, true)

	lrJSON, _ := json.Marshal(corev1LimitRange{Name: "default-limits", Namespace: "app"})
	plan := &RemediationPlan{
		ScanID: "scan-1",
		DryRun: true,
		Actions: []RemediationAction{
			{
				CheckID:    "CIS-5.7.1",
				ActionType: ActionCreate,
				TargetKind: "LimitRange",
				TargetName: "default-limits",
				TargetNS:   "app",
				PatchJSON:  lrJSON,
			},
		},
	}

	report, err := engine.Execute(context.Background(), plan, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusDryRun, report.Results[0].Status)
}
