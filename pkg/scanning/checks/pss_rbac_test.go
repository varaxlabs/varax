package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPSSEnforceLabelCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app",
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"},
		},
	})
	result := (&PSSEnforceLabelCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestPSSEnforceLabelCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "app"},
	})
	result := (&PSSEnforceLabelCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestPSSBaselineEnforceCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app",
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"},
		},
	})
	result := (&PSSBaselineEnforceCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestPSSBaselineEnforceCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app",
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": "privileged"},
		},
	})
	result := (&PSSBaselineEnforceCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestMeetsMinPSSLevel(t *testing.T) {
	assert.True(t, meetsMinPSSLevel("restricted", "baseline"))
	assert.True(t, meetsMinPSSLevel("baseline", "baseline"))
	assert.False(t, meetsMinPSSLevel("privileged", "baseline"))
	assert.False(t, meetsMinPSSLevel("invalid", "baseline"))
}

func TestRBACOverpermissiveCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "viewer"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get", "list"}, Resources: []string{"pods"}, APIGroups: []string{""}}},
	})
	result := (&RBACOverpermissiveCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestRBACOverpermissiveCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "admin-all"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{""}}},
	})
	result := (&RBACOverpermissiveCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestRBACSAPrivilegesCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset()
	result := (&RBACSAPrivilegesCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestRBACNamespaceScopeCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset()
	result := (&RBACNamespaceScopeCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
