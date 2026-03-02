package checks

import (
	"context"
	"testing"

	"github.com/varax/operator/pkg/models"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDefaultNamespaceCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "production"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
			},
		},
	)

	check := &DefaultNamespaceCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestDefaultNamespaceCheck_Pass_NoPods(t *testing.T) {
	client := fake.NewSimpleClientset()

	check := &DefaultNamespaceCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestDefaultNamespaceCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
			},
		},
	)

	check := &DefaultNamespaceCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Equal(t, "default", result.Evidence[0].Resource.Namespace)
}
