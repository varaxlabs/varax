package remediators

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestHostPIDRemediator(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "hostpid-pod", Namespace: "default"},
		},
	)

	rem := &HostPIDRemediator{}
	assert.Equal(t, "CIS-5.2.5", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "hostpid-pod", Namespace: "default"},
			Field:    "spec.hostPID",
			Value:    "true",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, remediation.ActionPatch, actions[0].ActionType)
	assert.Equal(t, "Pod", actions[0].TargetKind)
	assert.Contains(t, string(actions[0].PatchJSON), "hostPID")
}

func TestHostIPCRemediator(t *testing.T) {
	ctx := context.Background()
	objs := makeDeploymentPod("ipc-pod", "ipc-deploy", "prod")
	client := fake.NewSimpleClientset(objs[0].(*corev1.Pod), objs[1].(*appsv1.ReplicaSet))

	rem := &HostIPCRemediator{}
	assert.Equal(t, "CIS-5.2.6", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "ipc-pod", Namespace: "prod"},
			Field:    "spec.hostIPC",
			Value:    "true",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "Deployment", actions[0].TargetKind)
	assert.Equal(t, "ipc-deploy", actions[0].TargetName)
}

func TestHostNetworkRemediator(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "net-pod",
				Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "DaemonSet", Name: "net-ds"},
				},
			},
		},
	)

	rem := &HostNetworkRemediator{}
	assert.Equal(t, "CIS-5.2.7", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "net-pod", Namespace: "default"},
			Field:    "spec.hostNetwork",
			Value:    "true",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "DaemonSet", actions[0].TargetKind)
	assert.Equal(t, "net-ds", actions[0].TargetName)
}

func TestPodSpecRemediator_NoEvidence(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &HostPIDRemediator{}
	actions, err := rem.Plan(ctx, client, nil)
	require.NoError(t, err)
	assert.Empty(t, actions)
}
