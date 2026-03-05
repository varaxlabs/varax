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

// paginatedList is a generic helper that handles the pagination loop for any
// Kubernetes list call. The listFn receives ListOptions and returns the page's
// items, the continue token, and any error.
func paginatedList[T any](ctx context.Context, listFn func(ctx context.Context, opts metav1.ListOptions) ([]T, string, error)) ([]T, error) {
	var all []T
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		items, continueToken, err := listFn(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if continueToken == "" {
			return all, nil
		}
		opts.Continue = continueToken
	}
}

func paginatedListPods(ctx context.Context, client kubernetes.Interface, namespace string) ([]corev1.Pod, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]corev1.Pod, string, error) {
		list, err := client.CoreV1().Pods(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func paginatedListNamespaces(ctx context.Context, client kubernetes.Interface) ([]corev1.Namespace, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]corev1.Namespace, string, error) {
		list, err := client.CoreV1().Namespaces().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func paginatedListServiceAccounts(ctx context.Context, client kubernetes.Interface) ([]corev1.ServiceAccount, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]corev1.ServiceAccount, string, error) {
		list, err := client.CoreV1().ServiceAccounts("").List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func paginatedListClusterRoles(ctx context.Context, client kubernetes.Interface) ([]rbacv1.ClusterRole, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]rbacv1.ClusterRole, string, error) {
		list, err := client.RbacV1().ClusterRoles().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func paginatedListClusterRoleBindings(ctx context.Context, client kubernetes.Interface) ([]rbacv1.ClusterRoleBinding, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]rbacv1.ClusterRoleBinding, string, error) {
		list, err := client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func paginatedListRoles(ctx context.Context, client kubernetes.Interface) ([]rbacv1.Role, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]rbacv1.Role, string, error) {
		list, err := client.RbacV1().Roles("").List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func paginatedListRoleBindings(ctx context.Context, client kubernetes.Interface) ([]rbacv1.RoleBinding, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]rbacv1.RoleBinding, string, error) {
		list, err := client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func paginatedListNodes(ctx context.Context, client kubernetes.Interface) ([]corev1.Node, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]corev1.Node, string, error) {
		list, err := client.CoreV1().Nodes().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

func paginatedListNetworkPolicies(ctx context.Context, client kubernetes.Interface, namespace string) ([]networkingv1.NetworkPolicy, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]networkingv1.NetworkPolicy, string, error) {
		list, err := client.NetworkingV1().NetworkPolicies(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}
