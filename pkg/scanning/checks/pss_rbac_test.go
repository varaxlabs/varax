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

func TestPSSRestrictedEnforceCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app",
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"},
		},
	})
	result := (&PSSRestrictedEnforceCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestPSSRestrictedEnforceCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app",
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"},
		},
	})
	result := (&PSSRestrictedEnforceCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestPSSAuditLabelCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app",
			Labels: map[string]string{"pod-security.kubernetes.io/audit": "baseline"},
		},
	})
	result := (&PSSAuditLabelCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestPSSAuditLabelCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "app"},
	})
	result := (&PSSAuditLabelCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestPSSWarnLabelCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "app",
			Labels: map[string]string{"pod-security.kubernetes.io/warn": "restricted"},
		},
	})
	result := (&PSSWarnLabelCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestPSSWarnLabelCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "app"},
	})
	result := (&PSSWarnLabelCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
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

func TestRBACEscalationCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "viewer"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}, APIGroups: []string{""}}},
	})
	result := (&RBACEscalationCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestRBACEscalationCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "escalator"},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"create", "bind"},
				Resources: []string{"clusterrolebindings"},
				APIGroups: []string{"rbac.authorization.k8s.io"},
			}},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "escalator-binding"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "escalator"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "attacker"}},
		},
	)
	result := (&RBACEscalationCheck{}).Run(context.Background(), client)
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
