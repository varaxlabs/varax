package evidence

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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

	crs, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	snap.ClusterRoleCount = len(crs.Items)

	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	snap.ClusterRoleBindingCount = len(crbs.Items)

	for _, crb := range crbs.Items {
		if crb.RoleRef.Name == "cluster-admin" {
			snap.ClusterAdminBindings = append(snap.ClusterAdminBindings, crb.Name)
		}
	}

	roles, err := client.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	snap.RoleCount = len(roles.Items)

	rbs, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	snap.RoleBindingCount = len(rbs.Items)

	sas, err := client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	snap.ServiceAccountCount = len(sas.Items)

	return []EvidenceItem{{
		Category:    "RBAC",
		Description: "Snapshot of all RBAC resources in the cluster",
		Data:        snap,
		Timestamp:   now,
	}}, nil
}
