package scanning

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
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

func TestBuildCache_IncludesAllResourceTypes(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "rb-1", Namespace: "default"}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "ing-1", Namespace: "default"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d-1", Namespace: "default"}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "s-1", Namespace: "default"}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "pdb-1", Namespace: "default"}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "rq-1", Namespace: "default"}},
		&corev1.LimitRange{ObjectMeta: metav1.ObjectMeta{Name: "lr-1", Namespace: "default"}},
	)
	cache := BuildCache(context.Background(), client)
	assert.Len(t, cache.Nodes, 1)
	assert.Len(t, cache.RoleBindings, 1)
	assert.Len(t, cache.Ingresses, 1)
	assert.Len(t, cache.Deployments, 1)
	assert.Len(t, cache.StatefulSets, 1)
	assert.Len(t, cache.PDBs, 1)
	assert.Len(t, cache.ResourceQuotas, 1)
	assert.Len(t, cache.LimitRanges, 1)
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

func TestListIngresses_FromCache(t *testing.T) {
	cache := &ResourceCache{Ingresses: []networkingv1.Ingress{
		{ObjectMeta: metav1.ObjectMeta{Name: "ing-1", Namespace: "default"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "ing-2", Namespace: "app"}},
	}}
	ctx := ContextWithCache(context.Background(), cache)
	result, err := ListIngresses(ctx, nil, "app")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "ing-2", result[0].Name)
}

func TestListDeployments_FromCache(t *testing.T) {
	cache := &ResourceCache{Deployments: []appsv1.Deployment{
		{ObjectMeta: metav1.ObjectMeta{Name: "d-1", Namespace: "default"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "d-2", Namespace: "app"}},
	}}
	ctx := ContextWithCache(context.Background(), cache)
	result, err := ListDeployments(ctx, nil, "default")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListStatefulSets_FromCache(t *testing.T) {
	cache := &ResourceCache{StatefulSets: []appsv1.StatefulSet{
		{ObjectMeta: metav1.ObjectMeta{Name: "s-1", Namespace: "default"}},
	}}
	ctx := ContextWithCache(context.Background(), cache)
	result, err := ListStatefulSets(ctx, nil, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListPDBs_FromCache(t *testing.T) {
	cache := &ResourceCache{PDBs: []policyv1.PodDisruptionBudget{
		{ObjectMeta: metav1.ObjectMeta{Name: "p-1", Namespace: "default"}},
	}}
	ctx := ContextWithCache(context.Background(), cache)
	result, err := ListPDBs(ctx, nil, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListResourceQuotas_FromCache(t *testing.T) {
	cache := &ResourceCache{ResourceQuotas: []corev1.ResourceQuota{
		{ObjectMeta: metav1.ObjectMeta{Name: "rq-1", Namespace: "default"}},
	}}
	ctx := ContextWithCache(context.Background(), cache)
	result, err := ListResourceQuotas(ctx, nil, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListLimitRanges_FromCache(t *testing.T) {
	cache := &ResourceCache{LimitRanges: []corev1.LimitRange{
		{ObjectMeta: metav1.ObjectMeta{Name: "lr-1", Namespace: "default"}},
	}}
	ctx := ContextWithCache(context.Background(), cache)
	result, err := ListLimitRanges(ctx, nil, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListIngresses_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "ing-1", Namespace: "default"}},
	)
	result, err := ListIngresses(context.Background(), client, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListDeployments_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "deploy-1", Namespace: "default"}},
	)
	result, err := ListDeployments(context.Background(), client, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListStatefulSets_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "sts-1", Namespace: "default"}},
	)
	result, err := ListStatefulSets(context.Background(), client, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListPDBs_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "pdb-1", Namespace: "default"}},
	)
	result, err := ListPDBs(context.Background(), client, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListResourceQuotas_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "rq-1", Namespace: "default"}},
	)
	result, err := ListResourceQuotas(context.Background(), client, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListLimitRanges_NoCache(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.LimitRange{ObjectMeta: metav1.ObjectMeta{Name: "lr-1", Namespace: "default"}},
	)
	result, err := ListLimitRanges(context.Background(), client, "")
	require.NoError(t, err)
	assert.Len(t, result, 1)
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
