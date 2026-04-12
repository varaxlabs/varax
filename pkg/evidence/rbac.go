package evidence

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const evidencePageSize int64 = 500

// RBACSnapshot contains a summary of all RBAC resources in the cluster.
type RBACSnapshot struct {
	ClusterRoleCount        int              `json:"clusterRoleCount"`
	ClusterRoleBindingCount int              `json:"clusterRoleBindingCount"`
	RoleCount               int              `json:"roleCount"`
	RoleBindingCount        int              `json:"roleBindingCount"`
	ServiceAccountCount     int              `json:"serviceAccountCount"`
	ClusterAdminBindings    []AdminBinding   `json:"clusterAdminBindings,omitempty"`
	WildcardRoles           []string         `json:"wildcardRoles,omitempty"`
}

// AdminBinding describes a single cluster-admin binding with subject detail.
type AdminBinding struct {
	Name    string `json:"name"`
	Subject string `json:"subject"`
	Type    string `json:"type"` // "Group", "User", "ServiceAccount"
}

// SATokenMountSnapshot summarizes service account automount status.
type SATokenMountSnapshot struct {
	NamespacesAudited  int      `json:"namespacesAudited"`
	AutoMountCount     int      `json:"autoMountCount"`
	AutoMountAccounts  []string `json:"autoMountAccounts,omitempty"`
}

// NamespaceScopeSnapshot summarizes namespace-scoped vs cluster-scoped bindings.
type NamespaceScopeSnapshot struct {
	TotalRoleBindings       int `json:"totalRoleBindings"`
	NamespaceScopedCount    int `json:"namespaceScopedCount"`
	ClusterScopedCount      int `json:"clusterScopedCount"`
	NamespaceScopedPercent  int `json:"namespaceScopedPercent"`
}

func collectRBAC(ctx context.Context, client kubernetes.Interface) ([]EvidenceItem, error) {
	now := time.Now().UTC()
	snap := RBACSnapshot{}

	// ClusterRoles (paginated)
	opts := metav1.ListOptions{Limit: evidencePageSize}
	for {
		crs, err := client.RbacV1().ClusterRoles().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for _, cr := range crs.Items {
			snap.ClusterRoleCount++
			for _, rule := range cr.Rules {
				for _, res := range rule.Resources {
					if res == "*" {
						snap.WildcardRoles = append(snap.WildcardRoles, cr.Name)
						goto nextCR
					}
				}
				for _, verb := range rule.Verbs {
					if verb == "*" {
						snap.WildcardRoles = append(snap.WildcardRoles, cr.Name)
						goto nextCR
					}
				}
			}
		nextCR:
		}
		if crs.Continue == "" {
			break
		}
		opts.Continue = crs.Continue
	}

	// ClusterRoleBindings (paginated)
	opts = metav1.ListOptions{Limit: evidencePageSize}
	for {
		crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		snap.ClusterRoleBindingCount += len(crbs.Items)
		for _, crb := range crbs.Items {
			if crb.RoleRef.Name == "cluster-admin" {
				for _, subj := range crb.Subjects {
					snap.ClusterAdminBindings = append(snap.ClusterAdminBindings, AdminBinding{
						Name:    crb.Name,
						Subject: subj.Name,
						Type:    string(subj.Kind),
					})
				}
			}
		}
		if crbs.Continue == "" {
			break
		}
		opts.Continue = crbs.Continue
	}

	// Roles (paginated)
	opts = metav1.ListOptions{Limit: evidencePageSize}
	for {
		roles, err := client.RbacV1().Roles("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		snap.RoleCount += len(roles.Items)
		if roles.Continue == "" {
			break
		}
		opts.Continue = roles.Continue
	}

	// RoleBindings (paginated) — also compute namespace scope ratio
	scopeSnap := NamespaceScopeSnapshot{}
	opts = metav1.ListOptions{Limit: evidencePageSize}
	for {
		rbs, err := client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		snap.RoleBindingCount += len(rbs.Items)
		scopeSnap.NamespaceScopedCount += len(rbs.Items)
		if rbs.Continue == "" {
			break
		}
		opts.Continue = rbs.Continue
	}
	scopeSnap.ClusterScopedCount = snap.ClusterRoleBindingCount
	scopeSnap.TotalRoleBindings = scopeSnap.NamespaceScopedCount + scopeSnap.ClusterScopedCount
	if scopeSnap.TotalRoleBindings > 0 {
		scopeSnap.NamespaceScopedPercent = (scopeSnap.NamespaceScopedCount * 100) / scopeSnap.TotalRoleBindings
	}

	// ServiceAccounts (paginated) — also compute automount status
	saSnap := SATokenMountSnapshot{}
	auditedNS := make(map[string]bool)
	opts = metav1.ListOptions{Limit: evidencePageSize}
	for {
		sas, err := client.CoreV1().ServiceAccounts("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		snap.ServiceAccountCount += len(sas.Items)
		for _, sa := range sas.Items {
			auditedNS[sa.Namespace] = true
			if sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken {
				saSnap.AutoMountCount++
				saSnap.AutoMountAccounts = append(saSnap.AutoMountAccounts,
					fmt.Sprintf("%s/%s", sa.Namespace, sa.Name))
			}
		}
		if sas.Continue == "" {
			break
		}
		opts.Continue = sas.Continue
	}
	saSnap.NamespacesAudited = len(auditedNS)

	// Build evidence items
	items := []EvidenceItem{
		{
			Category:    "RBAC",
			Type:        "rbac-cluster-admin",
			Description: "RBAC ClusterRoleBinding inventory and cluster-admin scope",
			Data:        snap,
			Timestamp:   now,
			SHA256:      computeSHA256(snap),
		},
		{
			Category:    "RBAC",
			Type:        "rbac-sa-token-mount",
			Description: fmt.Sprintf("Service account token mount audit across %d namespaces", saSnap.NamespacesAudited),
			Data:        saSnap,
			Timestamp:   now,
			SHA256:      computeSHA256(saSnap),
		},
		{
			Category:    "RBAC",
			Type:        "rbac-namespace-scope",
			Description: fmt.Sprintf("Namespace scope ratio: %d%% namespace-scoped", scopeSnap.NamespaceScopedPercent),
			Data:        scopeSnap,
			Timestamp:   now,
			SHA256:      computeSHA256(scopeSnap),
		},
	}

	return items, nil
}
