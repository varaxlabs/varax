package checks

import (
	"context"
	"testing"

	"github.com/kubeshield/operator/pkg/models"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSATokenAutoMountCheck_Pass(t *testing.T) {
	automount := false
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "my-sa", Namespace: "default"},
			AutomountServiceAccountToken: &automount,
		},
	)

	check := &SATokenAutoMountCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestSATokenAutoMountCheck_FailAutoMountTrue(t *testing.T) {
	automount := true
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "my-sa", Namespace: "default"},
			AutomountServiceAccountToken: &automount,
		},
	)

	check := &SATokenAutoMountCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestSATokenAutoMountCheck_FailAutoMountNil(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "default"},
		},
	)

	check := &SATokenAutoMountCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestSATokenAutoMountCheck_SkipsSystemNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "kube-system"},
		},
	)

	check := &SATokenAutoMountCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}
