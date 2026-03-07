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

func makeDeploymentPod(podName, deployName, namespace string) []interface{} {
	return []interface{}{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: namespace,
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: deployName + "-abc"},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      deployName + "-abc",
				Namespace: namespace,
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "Deployment", Name: deployName},
				},
			},
		},
	}
}

func TestPrivilegeEscalationRemediator(t *testing.T) {
	ctx := context.Background()
	objs := makeDeploymentPod("web-abc-123", "web", "default")
	client := fake.NewSimpleClientset(objs[0].(*corev1.Pod), objs[1].(*appsv1.ReplicaSet))

	rem := &PrivilegeEscalationRemediator{}
	assert.Equal(t, "CIS-5.2.1", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "web-abc-123", Namespace: "default"},
			Field:    "spec.containers[app].securityContext.allowPrivilegeEscalation",
			Value:    "true or unset",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	require.Len(t, actions, 1)

	assert.Equal(t, remediation.ActionPatch, actions[0].ActionType)
	assert.Equal(t, "Deployment", actions[0].TargetKind)
	assert.Equal(t, "web", actions[0].TargetName)
	assert.Equal(t, "default", actions[0].TargetNS)
	assert.NotEmpty(t, actions[0].PatchJSON)
}

func TestRunAsNonRootRemediator(t *testing.T) {
	ctx := context.Background()
	objs := makeDeploymentPod("api-xyz-456", "api", "prod")
	client := fake.NewSimpleClientset(objs[0].(*corev1.Pod), objs[1].(*appsv1.ReplicaSet))

	rem := &RunAsNonRootRemediator{}
	assert.Equal(t, "CIS-5.2.2", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "api-xyz-456", Namespace: "prod"},
			Field:    "spec.containers[server].securityContext.runAsNonRoot",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "Deployment", actions[0].TargetKind)
	assert.Equal(t, "api", actions[0].TargetName)
}

func TestPrivilegedRemediator(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "default"},
		},
	)

	rem := &PrivilegedRemediator{}
	assert.Equal(t, "CIS-5.2.3", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "bare", Namespace: "default"},
			Field:    "spec.containers[main].securityContext.privileged",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "Pod", actions[0].TargetKind)
}

func TestDropCapabilitiesRemediator(t *testing.T) {
	ctx := context.Background()
	objs := makeDeploymentPod("web-abc-1", "web", "default")
	client := fake.NewSimpleClientset(objs[0].(*corev1.Pod), objs[1].(*appsv1.ReplicaSet))

	rem := &DropCapabilitiesRemediator{}
	assert.Equal(t, "CIS-5.2.4", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "web-abc-1", Namespace: "default"},
			Field:    "spec.containers[app].securityContext.capabilities.drop",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Contains(t, string(actions[0].PatchJSON), "ALL")
}

func TestSeccompRemediator(t *testing.T) {
	ctx := context.Background()
	objs := makeDeploymentPod("web-abc-1", "web", "default")
	client := fake.NewSimpleClientset(objs[0].(*corev1.Pod), objs[1].(*appsv1.ReplicaSet))

	rem := &SeccompRemediator{}
	assert.Equal(t, "CIS-5.7.2", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "web-abc-1", Namespace: "default"},
			Field:    "spec.securityContext.seccompProfile",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Contains(t, string(actions[0].PatchJSON), "RuntimeDefault")
	assert.Equal(t, "Deployment", actions[0].TargetKind)
}

func TestSecurityContextRemediator_DeduplicatesOwners(t *testing.T) {
	ctx := context.Background()
	objs := makeDeploymentPod("web-abc-1", "web", "default")
	client := fake.NewSimpleClientset(objs[0].(*corev1.Pod), objs[1].(*appsv1.ReplicaSet))

	rem := &PrivilegeEscalationRemediator{}

	// Two evidence items for same pod (different containers)
	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Pod", Name: "web-abc-1", Namespace: "default"},
			Field:    "spec.containers[app].securityContext.allowPrivilegeEscalation",
		},
		{
			Resource: models.Resource{Kind: "Pod", Name: "web-abc-1", Namespace: "default"},
			Field:    "spec.containers[sidecar].securityContext.allowPrivilegeEscalation",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	// One owner (Deployment web) but two containers -> two actions
	assert.Len(t, actions, 2)
	// Both should target the same deployment
	for _, a := range actions {
		assert.Equal(t, "Deployment", a.TargetKind)
		assert.Equal(t, "web", a.TargetName)
	}
}
