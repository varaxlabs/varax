package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResourceLimitsCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("250m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
					},
				},
			},
		},
	)

	result := (&ResourceLimitsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestResourceLimitsCheck_Fail_NoLimits(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	result := (&ResourceLimitsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Contains(t, result.Evidence[0].Value, "limits.cpu")
}

func TestResourceLimitsCheck_Fail_PartialLimits(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "partial-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("500m"),
							},
						},
					},
				},
			},
		},
	)

	result := (&ResourceLimitsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Contains(t, result.Evidence[0].Value, "limits.memory")
}

func TestResourceLimitsCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "proxy"},
				},
			},
		},
	)

	result := (&ResourceLimitsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
