package remediation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestIsSystemNamespace(t *testing.T) {
	assert.True(t, isSystemNamespace("kube-system"))
	assert.True(t, isSystemNamespace("kube-public"))
	assert.True(t, isSystemNamespace("kube-node-lease"))
	assert.False(t, isSystemNamespace("default"))
	assert.False(t, isSystemNamespace("app"))
}

func TestHasExclusionLabel(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "skip-me",
				Namespace: "default",
				Labels:    map[string]string{exclusionLabel: "true"},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dont-skip",
				Namespace: "default",
			},
		},
	)

	assert.True(t, hasExclusionLabel(ctx, client, "Deployment", "default", "skip-me"))
	assert.False(t, hasExclusionLabel(ctx, client, "Deployment", "default", "dont-skip"))
	assert.False(t, hasExclusionLabel(ctx, client, "Deployment", "default", "nonexistent"))
}

func TestHasExclusionLabel_ServiceAccount(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sa-skip",
				Namespace: "default",
				Labels:    map[string]string{exclusionLabel: "true"},
			},
		},
	)

	assert.True(t, hasExclusionLabel(ctx, client, "ServiceAccount", "default", "sa-skip"))
}

func TestHasExclusionLabel_StatefulSet(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "db",
				Namespace: "data",
				Labels:    map[string]string{exclusionLabel: "true"},
			},
		},
	)

	assert.True(t, hasExclusionLabel(ctx, client, "StatefulSet", "data", "db"))
}

func TestHasExclusionLabel_DaemonSet(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "agent",
				Namespace: "monitoring",
				Labels:    map[string]string{exclusionLabel: "true"},
			},
		},
	)

	assert.True(t, hasExclusionLabel(ctx, client, "DaemonSet", "monitoring", "agent"))
}

func TestHasExclusionLabel_Pod(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "skip-pod",
				Namespace: "default",
				Labels:    map[string]string{exclusionLabel: "true"},
			},
		},
	)

	assert.True(t, hasExclusionLabel(ctx, client, "Pod", "default", "skip-pod"))
}

func TestHasExclusionLabel_UnknownKind(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	assert.False(t, hasExclusionLabel(ctx, client, "CronJob", "default", "something"))
}

func TestAnnotateResource(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		},
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "data"},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "monitoring"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "default"},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "default"},
		},
	)

	assert.NoError(t, annotateResource(ctx, client, "Deployment", "default", "web"))
	assert.NoError(t, annotateResource(ctx, client, "StatefulSet", "data", "db"))
	assert.NoError(t, annotateResource(ctx, client, "DaemonSet", "monitoring", "agent"))
	assert.NoError(t, annotateResource(ctx, client, "Pod", "default", "bare"))
	assert.NoError(t, annotateResource(ctx, client, "ServiceAccount", "default", "sa"))
}
