package remediation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveOwner_Deployment(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-abc-123",
				Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: "web-abc"},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-abc",
				Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "Deployment", Name: "web"},
				},
			},
		},
	)

	owner, err := ResolveOwner(ctx, client, "default", "web-abc-123")
	require.NoError(t, err)
	assert.Equal(t, "Deployment", owner.Kind)
	assert.Equal(t, "web", owner.Name)
	assert.Equal(t, "default", owner.Namespace)
}

func TestResolveOwner_StatefulSet(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "db-0",
				Namespace: "data",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "StatefulSet", Name: "db"},
				},
			},
		},
	)

	owner, err := ResolveOwner(ctx, client, "data", "db-0")
	require.NoError(t, err)
	assert.Equal(t, "StatefulSet", owner.Kind)
	assert.Equal(t, "db", owner.Name)
}

func TestResolveOwner_DaemonSet(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "agent-xyz",
				Namespace: "monitoring",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "DaemonSet", Name: "agent"},
				},
			},
		},
	)

	owner, err := ResolveOwner(ctx, client, "monitoring", "agent-xyz")
	require.NoError(t, err)
	assert.Equal(t, "DaemonSet", owner.Kind)
	assert.Equal(t, "agent", owner.Name)
}

func TestResolveOwner_BarePod(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "standalone",
				Namespace: "default",
			},
		},
	)

	owner, err := ResolveOwner(ctx, client, "default", "standalone")
	require.NoError(t, err)
	assert.Equal(t, "Pod", owner.Kind)
	assert.Equal(t, "standalone", owner.Name)
}

func TestResolveOwner_NotFound(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	_, err := ResolveOwner(ctx, client, "default", "nonexistent")
	assert.Error(t, err)
}

func TestResolveOwner_ReplicaSetWithoutDeployment(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "orphan-pod",
				Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: "orphan-rs"},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "orphan-rs",
				Namespace: "default",
			},
		},
	)

	owner, err := ResolveOwner(ctx, client, "default", "orphan-pod")
	require.NoError(t, err)
	assert.Equal(t, "Pod", owner.Kind)
}
