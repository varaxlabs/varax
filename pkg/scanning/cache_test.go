package scanning

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestListNodes_FromCache(t *testing.T) {
	nodes := []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}}
	cache := &ResourceCache{Nodes: nodes}
	ctx := ContextWithCache(context.Background(), cache)

	result, err := ListNodes(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "node-1", result[0].Name)
}

func TestListNodes_FromAPI(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-api"},
	})
	result, err := ListNodes(context.Background(), client)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "node-api", result[0].Name)
}

func TestListRoleBindings_FromCache(t *testing.T) {
	rbs := []rbacv1.RoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "rb-1", Namespace: "default"}}}
	cache := &ResourceCache{RoleBindings: rbs}
	ctx := ContextWithCache(context.Background(), cache)

	result, err := ListRoleBindings(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "rb-1", result[0].Name)
}

func TestListRoleBindings_FromAPI(t *testing.T) {
	client := fake.NewSimpleClientset(&rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-api", Namespace: "default"},
	})
	result, err := ListRoleBindings(context.Background(), client)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "rb-api", result[0].Name)
}

func TestBuildCache_IncludesNodesAndRoleBindings(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "rb-1", Namespace: "default"}},
	)
	cache := BuildCache(context.Background(), client)
	assert.Len(t, cache.Nodes, 1)
	assert.Len(t, cache.RoleBindings, 1)
}

// Tests for List* functions without cache (fallthrough to paginatedList*)

func TestListPods_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "kube-system"}},
	)
	ctx := context.Background() // no cache

	// All namespaces
	result, err := ListPods(ctx, client, "")
	require.NoError(t, err)
	assert.Len(t, result, 2)

	// Filtered by namespace
	result, err = ListPods(ctx, client, "default")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "pod-1", result[0].Name)
}

func TestListNamespaces_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	)
	result, err := ListNamespaces(context.Background(), client)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestListServiceAccounts_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa-1", Namespace: "default"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa-2", Namespace: "kube-system"}},
	)
	result, err := ListServiceAccounts(context.Background(), client)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestListClusterRoles_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "cr-1"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "cr-2"}},
	)
	result, err := ListClusterRoles(context.Background(), client)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestListClusterRoleBindings_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "crb-1"}},
	)
	result, err := ListClusterRoleBindings(context.Background(), client)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "crb-1", result[0].Name)
}

func TestListRoles_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "role-1", Namespace: "default"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "role-2", Namespace: "app"}},
	)
	result, err := ListRoles(context.Background(), client)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestListNetworkPolicies_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "np-1", Namespace: "default"}},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "np-2", Namespace: "app"}},
	)
	ctx := context.Background() // no cache

	// All namespaces
	result, err := ListNetworkPolicies(ctx, client, "")
	require.NoError(t, err)
	assert.Len(t, result, 2)

	// Filtered by namespace
	result, err = ListNetworkPolicies(ctx, client, "app")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "np-2", result[0].Name)
}

func TestCacheFromContext_NilWhenNoCache(t *testing.T) {
	ctx := context.Background()
	cache := CacheFromContext(ctx)
	assert.Nil(t, cache)
}

// Test for BySection in Registry

func TestBySection(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&sectionCheck{id: "CIS-5.1.1", section: "5.1.1"})
	registry.Register(&sectionCheck{id: "CIS-5.1.2", section: "5.1.2"})
	registry.Register(&sectionCheck{id: "CIS-5.2.1", section: "5.2.1"})
	registry.Register(&sectionCheck{id: "CIS-4.1.1", section: "4.1.1"})

	// Match all 5.1.* checks
	result := registry.BySection("5.1")
	assert.Len(t, result, 2)

	// Match all 5.* checks
	result = registry.BySection("5")
	assert.Len(t, result, 3)

	// Match exact section
	result = registry.BySection("4.1.1")
	assert.Len(t, result, 1)
	assert.Equal(t, "CIS-4.1.1", result[0].ID())

	// No match
	result = registry.BySection("9")
	assert.Len(t, result, 0)
}

// sectionCheck is a minimal Check implementation for testing BySection.
type sectionCheck struct {
	id      string
	section string
}

func (s *sectionCheck) ID() string          { return s.id }
func (s *sectionCheck) Name() string        { return s.id }
func (s *sectionCheck) Description() string { return "test" }
func (s *sectionCheck) Severity() models.Severity {
	return models.SeverityMedium
}
func (s *sectionCheck) Benchmark() string { return "CIS" }
func (s *sectionCheck) Section() string   { return s.section }
func (s *sectionCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return models.CheckResult{ID: s.id, Status: models.StatusPass}
}
