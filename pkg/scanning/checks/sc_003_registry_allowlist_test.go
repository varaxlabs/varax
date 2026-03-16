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

func TestRegistryAllowlistCheck_Pass_DockerHub(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:1.25"},
				},
			},
		},
	)

	result := (&RegistryAllowlistCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestRegistryAllowlistCheck_Pass_GCR(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "gcr.io/myproject/myapp:v1"},
				},
			},
		},
	)

	result := (&RegistryAllowlistCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestRegistryAllowlistCheck_Pass_ECR(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:v1"},
				},
			},
		},
	)

	result := (&RegistryAllowlistCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestRegistryAllowlistCheck_Fail_UnknownRegistry(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "evil-registry.io/malware:latest"},
				},
			},
		},
	)

	result := (&RegistryAllowlistCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Equal(t, "evil-registry.io", result.Evidence[0].Value)
}

func TestRegistryAllowlistCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "proxy", Image: "evil-registry.io/proxy:v1"},
				},
			},
		},
	)

	result := (&RegistryAllowlistCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
