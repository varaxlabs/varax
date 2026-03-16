package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLabelStandardsCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "good-deploy", Namespace: "default",
				Labels: map[string]string{
					"app.kubernetes.io/name":       "myapp",
					"app.kubernetes.io/component":  "api",
					"app.kubernetes.io/managed-by": "helm",
				},
			},
		},
	)

	result := (&LabelStandardsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestLabelStandardsCheck_Fail_MissingLabels(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "bad-deploy", Namespace: "default",
				Labels: map[string]string{"app": "myapp"},
			},
		},
	)

	result := (&LabelStandardsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Contains(t, result.Evidence[0].Value, "app.kubernetes.io/name")
}

func TestLabelStandardsCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "system-deploy", Namespace: "kube-system"},
		},
	)

	result := (&LabelStandardsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
