package checks

import (
	"context"
	"testing"

	"github.com/kubeshield/operator/pkg/models"
	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEscalatePermsCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-role"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"get", "list", "watch"}, Resources: []string{"pods"}},
			},
		},
	)

	check := &EscalatePermsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestEscalatePermsCheck_Fail_Bind(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "binder-role"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"bind"}, Resources: []string{"clusterroles"}},
			},
		},
	)

	check := &EscalatePermsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestEscalatePermsCheck_Fail_Escalate(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "escalate-role"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"escalate"}, Resources: []string{"clusterroles"}},
			},
		},
	)

	check := &EscalatePermsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
}

func TestEscalatePermsCheck_Fail_Impersonate(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "impersonate-role", Namespace: "default"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"impersonate"}, Resources: []string{"users"}},
			},
		},
	)

	check := &EscalatePermsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
}

func TestEscalatePermsCheck_SkipsSystemRoles(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "system:controller:clusterrole-aggregation-controller"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"escalate", "bind"}, Resources: []string{"clusterroles"}},
			},
		},
	)

	check := &EscalatePermsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}
