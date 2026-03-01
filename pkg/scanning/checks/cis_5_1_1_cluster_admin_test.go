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

func TestClusterAdminCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "system:masters"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "system:masters"},
			},
		},
	)

	check := &ClusterAdminCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
	assert.Empty(t, result.Evidence)
}

func TestClusterAdminCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "dev-user"},
				{Kind: "ServiceAccount", Name: "default", Namespace: "default"},
			},
		},
	)

	check := &ClusterAdminCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 2)
}

func TestClusterAdminCheck_NoBindings(t *testing.T) {
	client := fake.NewSimpleClientset()

	check := &ClusterAdminCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}
