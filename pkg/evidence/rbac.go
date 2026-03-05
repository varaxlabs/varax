package evidence

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const evidencePageSize int64 = 500

type rbacSnapshot struct {
	ClusterRoleCount        int      `json:"clusterRoleCount"`
	ClusterRoleBindingCount int      `json:"clusterRoleBindingCount"`
	RoleCount               int      `json:"roleCount"`
	RoleBindingCount        int      `json:"roleBindingCount"`
	ServiceAccountCount     int      `json:"serviceAccountCount"`
	ClusterAdminBindings    []string `json:"clusterAdminBindings,omitempty"`
}

func collectRBAC(ctx context.Context, client kubernetes.Interface) ([]EvidenceItem, error) {
	now := time.Now().UTC()
	snap := rbacSnapshot{}

	// ClusterRoles (paginated)
	opts := metav1.ListOptions{Limit: evidencePageSize}
	for {
		crs, err := client.RbacV1().ClusterRoles().List(ctx, opts)
		if err != nil {
			return nil, err
		}
		snap.ClusterRoleCount += len(crs.Items)
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
				snap.ClusterAdminBindings = append(snap.ClusterAdminBindings, crb.Name)
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

	// RoleBindings (paginated)
	opts = metav1.ListOptions{Limit: evidencePageSize}
	for {
		rbs, err := client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		snap.RoleBindingCount += len(rbs.Items)
		if rbs.Continue == "" {
			break
		}
		opts.Continue = rbs.Continue
	}

	// ServiceAccounts (paginated)
	opts = metav1.ListOptions{Limit: evidencePageSize}
	for {
		sas, err := client.CoreV1().ServiceAccounts("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		snap.ServiceAccountCount += len(sas.Items)
		if sas.Continue == "" {
			break
		}
		opts.Continue = sas.Continue
	}

	return []EvidenceItem{{
		Category:    "RBAC",
		Description: "Snapshot of all RBAC resources in the cluster",
		Data:        snap,
		Timestamp:   now,
	}}, nil
}
