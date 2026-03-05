package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzeOverPermissiveRoles(t *testing.T) {
	clusterRoles := []rbacv1.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-all"},
			Rules:      []rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"pods"}, APIGroups: []string{""}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "system:kube-proxy"},
			Rules:      []rbacv1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{""}}},
		},
	}
	findings := AnalyzeOverPermissiveRoles(clusterRoles, nil)
	assert.Len(t, findings, 1)
	assert.Equal(t, "admin-all", findings[0].Resource)
}

func TestAnalyzeEscalationPaths(t *testing.T) {
	clusterRoles := []rbacv1.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalator"},
			Rules: []rbacv1.PolicyRule{{
				Verbs:     []string{"create"},
				Resources: []string{"clusterrolebindings"},
				APIGroups: []string{"rbac.authorization.k8s.io"},
			}},
		},
	}
	findings := AnalyzeEscalationPaths(clusterRoles, nil)
	assert.Len(t, findings, 1)
}

func TestAnalyzeSAPrivileges(t *testing.T) {
	bindings := []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "sa-admin"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "bad-sa", Namespace: "default"}},
		},
	}
	sas := []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "bad-sa", Namespace: "default"}}}
	findings := AnalyzeSAPrivileges(sas, bindings)
	assert.Len(t, findings, 1)
}

func TestAnalyzeNamespaceScope(t *testing.T) {
	rbs := []rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rb-1", Namespace: "app"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
		},
	}
	findings := AnalyzeNamespaceScope(nil, rbs)
	assert.Len(t, findings, 1)
}
