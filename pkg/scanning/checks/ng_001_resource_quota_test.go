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

func TestResourceQuotaCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "quota", Namespace: "default"}},
	)

	result := (&ResourceQuotaCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestResourceQuotaCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
	)

	result := (&ResourceQuotaCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestResourceQuotaCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	)

	result := (&ResourceQuotaCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
