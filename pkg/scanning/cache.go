package scanning

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const listPageSize int64 = 500

// ResourceCache holds pre-fetched Kubernetes resources for use by checks.
// This avoids redundant API calls (e.g., 13 checks all listing pods) and
// uses paginated fetching to prevent OOM on large clusters.
type ResourceCache struct {
	Pods                []corev1.Pod
	Namespaces          []corev1.Namespace
	ServiceAccounts     []corev1.ServiceAccount
	ClusterRoles        []rbacv1.ClusterRole
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	Roles               []rbacv1.Role
	RoleBindings        []rbacv1.RoleBinding
	Nodes               []corev1.Node
	NetworkPolicies     []networkingv1.NetworkPolicy
}

type cacheContextKey struct{}

// ContextWithCache returns a new context with the given ResourceCache attached.
func ContextWithCache(ctx context.Context, cache *ResourceCache) context.Context {
	return context.WithValue(ctx, cacheContextKey{}, cache)
}

// CacheFromContext extracts a ResourceCache from the context, or nil if none.
func CacheFromContext(ctx context.Context) *ResourceCache {
	if c, ok := ctx.Value(cacheContextKey{}).(*ResourceCache); ok {
		return c
	}
	return nil
}

// BuildCache pre-fetches all resources needed by checks using paginated list calls.
// Individual resource fetch failures are non-fatal; checks fall back to direct API calls.
func BuildCache(ctx context.Context, client kubernetes.Interface) *ResourceCache {
	cache := &ResourceCache{}
	cache.Pods, _ = paginatedListPods(ctx, client, "")
	cache.Namespaces, _ = paginatedListNamespaces(ctx, client)
	cache.ServiceAccounts, _ = paginatedListServiceAccounts(ctx, client)
	cache.ClusterRoles, _ = paginatedListClusterRoles(ctx, client)
	cache.ClusterRoleBindings, _ = paginatedListClusterRoleBindings(ctx, client)
	cache.Roles, _ = paginatedListRoles(ctx, client)
	cache.RoleBindings, _ = paginatedListRoleBindings(ctx, client)
	cache.Nodes, _ = paginatedListNodes(ctx, client)
	cache.NetworkPolicies, _ = paginatedListNetworkPolicies(ctx, client, "")
	return cache
}

// ListPods returns pods from cache if available, otherwise fetches with pagination.
func ListPods(ctx context.Context, client kubernetes.Interface, namespace string) ([]corev1.Pod, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.Pods != nil {
		if namespace == "" {
			return cache.Pods, nil
		}
		var filtered []corev1.Pod
		for _, p := range cache.Pods {
			if p.Namespace == namespace {
				filtered = append(filtered, p)
			}
		}
		return filtered, nil
	}
	return paginatedListPods(ctx, client, namespace)
}

// ListNamespaces returns namespaces from cache or fetches with pagination.
func ListNamespaces(ctx context.Context, client kubernetes.Interface) ([]corev1.Namespace, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.Namespaces != nil {
		return cache.Namespaces, nil
	}
	return paginatedListNamespaces(ctx, client)
}

// ListServiceAccounts returns service accounts from cache or fetches with pagination.
func ListServiceAccounts(ctx context.Context, client kubernetes.Interface) ([]corev1.ServiceAccount, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.ServiceAccounts != nil {
		return cache.ServiceAccounts, nil
	}
	return paginatedListServiceAccounts(ctx, client)
}

// ListClusterRoles returns cluster roles from cache or fetches with pagination.
func ListClusterRoles(ctx context.Context, client kubernetes.Interface) ([]rbacv1.ClusterRole, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.ClusterRoles != nil {
		return cache.ClusterRoles, nil
	}
	return paginatedListClusterRoles(ctx, client)
}

// ListClusterRoleBindings returns cluster role bindings from cache or fetches with pagination.
func ListClusterRoleBindings(ctx context.Context, client kubernetes.Interface) ([]rbacv1.ClusterRoleBinding, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.ClusterRoleBindings != nil {
		return cache.ClusterRoleBindings, nil
	}
	return paginatedListClusterRoleBindings(ctx, client)
}

// ListRoles returns roles from cache or fetches with pagination.
func ListRoles(ctx context.Context, client kubernetes.Interface) ([]rbacv1.Role, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.Roles != nil {
		return cache.Roles, nil
	}
	return paginatedListRoles(ctx, client)
}

// ListRoleBindings returns role bindings from cache or fetches with pagination.
func ListRoleBindings(ctx context.Context, client kubernetes.Interface) ([]rbacv1.RoleBinding, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.RoleBindings != nil {
		return cache.RoleBindings, nil
	}
	return paginatedListRoleBindings(ctx, client)
}

// ListNodes returns nodes from cache or fetches with pagination.
func ListNodes(ctx context.Context, client kubernetes.Interface) ([]corev1.Node, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.Nodes != nil {
		return cache.Nodes, nil
	}
	return paginatedListNodes(ctx, client)
}

// ListNetworkPolicies returns network policies from cache or fetches with pagination.
func ListNetworkPolicies(ctx context.Context, client kubernetes.Interface, namespace string) ([]networkingv1.NetworkPolicy, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.NetworkPolicies != nil {
		if namespace == "" {
			return cache.NetworkPolicies, nil
		}
		var filtered []networkingv1.NetworkPolicy
		for _, np := range cache.NetworkPolicies {
			if np.Namespace == namespace {
				filtered = append(filtered, np)
			}
		}
		return filtered, nil
	}
	return paginatedListNetworkPolicies(ctx, client, namespace)
}

// Paginated list implementations

func paginatedListPods(ctx context.Context, client kubernetes.Interface, namespace string) ([]corev1.Pod, error) {
	var all []corev1.Pod
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.CoreV1().Pods(namespace).List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}

func paginatedListNamespaces(ctx context.Context, client kubernetes.Interface) ([]corev1.Namespace, error) {
	var all []corev1.Namespace
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.CoreV1().Namespaces().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}

func paginatedListServiceAccounts(ctx context.Context, client kubernetes.Interface) ([]corev1.ServiceAccount, error) {
	var all []corev1.ServiceAccount
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.CoreV1().ServiceAccounts("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}

func paginatedListClusterRoles(ctx context.Context, client kubernetes.Interface) ([]rbacv1.ClusterRole, error) {
	var all []rbacv1.ClusterRole
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.RbacV1().ClusterRoles().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}

func paginatedListClusterRoleBindings(ctx context.Context, client kubernetes.Interface) ([]rbacv1.ClusterRoleBinding, error) {
	var all []rbacv1.ClusterRoleBinding
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}

func paginatedListRoles(ctx context.Context, client kubernetes.Interface) ([]rbacv1.Role, error) {
	var all []rbacv1.Role
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.RbacV1().Roles("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}

func paginatedListRoleBindings(ctx context.Context, client kubernetes.Interface) ([]rbacv1.RoleBinding, error) {
	var all []rbacv1.RoleBinding
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}

func paginatedListNodes(ctx context.Context, client kubernetes.Interface) ([]corev1.Node, error) {
	var all []corev1.Node
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.CoreV1().Nodes().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}

func paginatedListNetworkPolicies(ctx context.Context, client kubernetes.Interface, namespace string) ([]networkingv1.NetworkPolicy, error) {
	var all []networkingv1.NetworkPolicy
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		list, err := client.NetworkingV1().NetworkPolicies(namespace).List(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, list.Items...)
		if list.Continue == "" {
			return all, nil
		}
		opts.Continue = list.Continue
	}
}
