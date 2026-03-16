package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestImageTagPolicyCheck_Pass_Digest(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "gcr.io/project/app@sha256:abc123def456"},
				},
			},
		},
	)

	result := (&ImageTagPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestImageTagPolicyCheck_Pass_SemverTag(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:1.25.3"},
				},
			},
		},
	)

	result := (&ImageTagPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestImageTagPolicyCheck_Fail_Latest(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:latest"},
				},
			},
		},
	)

	result := (&ImageTagPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Contains(t, result.Evidence[0].Value, "nginx:latest")
}

func TestImageTagPolicyCheck_Fail_NoTag(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx"},
				},
			},
		},
	)

	result := (&ImageTagPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestImageTagPolicyCheck_Fail_MutableTag(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "myapp:dev"},
				},
			},
		},
	)

	result := (&ImageTagPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestImageTagPolicyCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "proxy", Image: "kube-proxy:latest"},
				},
			},
		},
	)

	result := (&ImageTagPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
