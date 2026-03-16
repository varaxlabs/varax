package scanning

import (
	"context"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
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
	Ingresses           []networkingv1.Ingress
	Deployments         []appsv1.Deployment
	StatefulSets        []appsv1.StatefulSet
	PDBs                []policyv1.PodDisruptionBudget
	ResourceQuotas      []corev1.ResourceQuota
	LimitRanges         []corev1.LimitRange
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
	var wg sync.WaitGroup
	fetch := func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}
	fetch(func() { cache.Pods, _ = paginatedListPods(ctx, client, "") })
	fetch(func() { cache.Namespaces, _ = paginatedListNamespaces(ctx, client) })
	fetch(func() { cache.ServiceAccounts, _ = paginatedListServiceAccounts(ctx, client) })
	fetch(func() { cache.ClusterRoles, _ = paginatedListClusterRoles(ctx, client) })
	fetch(func() { cache.ClusterRoleBindings, _ = paginatedListClusterRoleBindings(ctx, client) })
	fetch(func() { cache.Roles, _ = paginatedListRoles(ctx, client) })
	fetch(func() { cache.RoleBindings, _ = paginatedListRoleBindings(ctx, client) })
	fetch(func() { cache.Nodes, _ = paginatedListNodes(ctx, client) })
	fetch(func() { cache.NetworkPolicies, _ = paginatedListNetworkPolicies(ctx, client, "") })
	fetch(func() { cache.Ingresses, _ = paginatedListIngresses(ctx, client, "") })
	fetch(func() { cache.Deployments, _ = paginatedListDeployments(ctx, client, "") })
	fetch(func() { cache.StatefulSets, _ = paginatedListStatefulSets(ctx, client, "") })
	fetch(func() { cache.PDBs, _ = paginatedListPDBs(ctx, client, "") })
	fetch(func() { cache.ResourceQuotas, _ = paginatedListResourceQuotas(ctx, client, "") })
	fetch(func() { cache.LimitRanges, _ = paginatedListLimitRanges(ctx, client, "") })
	wg.Wait()
	return cache
}

// filterByNamespace returns items matching the given namespace, or all items if
// namespace is empty. The pointer constraint P satisfies GetNamespace() while
// allowing the slice to hold value types (e.g. []corev1.Pod).
func filterByNamespace[T any, P interface {
	*T
	GetNamespace() string
}](items []T, namespace string) []T {
	if namespace == "" {
		return items
	}
	var filtered []T
	for i := range items {
		if P(&items[i]).GetNamespace() == namespace {
			filtered = append(filtered, items[i])
		}
	}
	return filtered
}

// ListPods returns pods from cache if available, otherwise fetches with pagination.
func ListPods(ctx context.Context, client kubernetes.Interface, namespace string) ([]corev1.Pod, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.Pods != nil {
		return filterByNamespace(cache.Pods, namespace), nil
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
		return filterByNamespace(cache.NetworkPolicies, namespace), nil
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
			if all == nil {
				all = make([]T, 0)
			}
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

// ListIngresses returns ingresses from cache or fetches with pagination.
func ListIngresses(ctx context.Context, client kubernetes.Interface, namespace string) ([]networkingv1.Ingress, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.Ingresses != nil {
		return filterByNamespace(cache.Ingresses, namespace), nil
	}
	return paginatedListIngresses(ctx, client, namespace)
}

func paginatedListIngresses(ctx context.Context, client kubernetes.Interface, namespace string) ([]networkingv1.Ingress, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]networkingv1.Ingress, string, error) {
		list, err := client.NetworkingV1().Ingresses(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

// ListDeployments returns deployments from cache or fetches with pagination.
func ListDeployments(ctx context.Context, client kubernetes.Interface, namespace string) ([]appsv1.Deployment, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.Deployments != nil {
		return filterByNamespace(cache.Deployments, namespace), nil
	}
	return paginatedListDeployments(ctx, client, namespace)
}

func paginatedListDeployments(ctx context.Context, client kubernetes.Interface, namespace string) ([]appsv1.Deployment, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]appsv1.Deployment, string, error) {
		list, err := client.AppsV1().Deployments(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

// ListStatefulSets returns statefulsets from cache or fetches with pagination.
func ListStatefulSets(ctx context.Context, client kubernetes.Interface, namespace string) ([]appsv1.StatefulSet, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.StatefulSets != nil {
		return filterByNamespace(cache.StatefulSets, namespace), nil
	}
	return paginatedListStatefulSets(ctx, client, namespace)
}

func paginatedListStatefulSets(ctx context.Context, client kubernetes.Interface, namespace string) ([]appsv1.StatefulSet, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]appsv1.StatefulSet, string, error) {
		list, err := client.AppsV1().StatefulSets(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

// ListPDBs returns pod disruption budgets from cache or fetches with pagination.
func ListPDBs(ctx context.Context, client kubernetes.Interface, namespace string) ([]policyv1.PodDisruptionBudget, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.PDBs != nil {
		return filterByNamespace(cache.PDBs, namespace), nil
	}
	return paginatedListPDBs(ctx, client, namespace)
}

func paginatedListPDBs(ctx context.Context, client kubernetes.Interface, namespace string) ([]policyv1.PodDisruptionBudget, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]policyv1.PodDisruptionBudget, string, error) {
		list, err := client.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

// ListResourceQuotas returns resource quotas from cache or fetches with pagination.
func ListResourceQuotas(ctx context.Context, client kubernetes.Interface, namespace string) ([]corev1.ResourceQuota, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.ResourceQuotas != nil {
		return filterByNamespace(cache.ResourceQuotas, namespace), nil
	}
	return paginatedListResourceQuotas(ctx, client, namespace)
}

func paginatedListResourceQuotas(ctx context.Context, client kubernetes.Interface, namespace string) ([]corev1.ResourceQuota, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]corev1.ResourceQuota, string, error) {
		list, err := client.CoreV1().ResourceQuotas(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}

// ListLimitRanges returns limit ranges from cache or fetches with pagination.
func ListLimitRanges(ctx context.Context, client kubernetes.Interface, namespace string) ([]corev1.LimitRange, error) {
	if cache := CacheFromContext(ctx); cache != nil && cache.LimitRanges != nil {
		return filterByNamespace(cache.LimitRanges, namespace), nil
	}
	return paginatedListLimitRanges(ctx, client, namespace)
}

func paginatedListLimitRanges(ctx context.Context, client kubernetes.Interface, namespace string) ([]corev1.LimitRange, error) {
	return paginatedList(ctx, func(ctx context.Context, opts metav1.ListOptions) ([]corev1.LimitRange, string, error) {
		list, err := client.CoreV1().LimitRanges(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
}
