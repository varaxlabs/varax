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

func TestSBOMAttestationCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "attested-pod", Namespace: "default",
				Annotations: map[string]string{"io.syft.sbom": "true"},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "myapp:v1"}}},
		},
	)

	result := (&SBOMAttestationCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestSBOMAttestationCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "no-sbom-pod", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "myapp:v1"}}},
		},
	)

	result := (&SBOMAttestationCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestSBOMAttestationCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "proxy"}}},
		},
	)

	result := (&SBOMAttestationCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
