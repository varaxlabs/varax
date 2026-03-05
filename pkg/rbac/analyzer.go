package rbac

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	corev1 "k8s.io/api/core/v1"
)

// Finding represents a single RBAC analysis finding.
type Finding struct {
	Resource    string
	Namespace   string
	Description string
}

// AnalyzeOverPermissiveRoles finds roles with wildcard verbs/resources.
func AnalyzeOverPermissiveRoles(clusterRoles []rbacv1.ClusterRole, roles []rbacv1.Role) []Finding {
	var findings []Finding

	for _, cr := range clusterRoles {
		if isSystemResource(cr.Name) {
			continue
		}
		for _, rule := range cr.Rules {
			if hasWildcard(rule.Verbs) || hasWildcard(rule.Resources) {
				findings = append(findings, Finding{
					Resource:    cr.Name,
					Description: fmt.Sprintf("ClusterRole '%s' has wildcard permissions", cr.Name),
				})
				break
			}
		}
	}

	for _, r := range roles {
		for _, rule := range r.Rules {
			if hasWildcard(rule.Verbs) || hasWildcard(rule.Resources) {
				findings = append(findings, Finding{
					Resource:    r.Name,
					Namespace:   r.Namespace,
					Description: fmt.Sprintf("Role '%s/%s' has wildcard permissions", r.Namespace, r.Name),
				})
				break
			}
		}
	}

	return findings
}

// AnalyzeEscalationPaths finds roles that can create/modify bindings.
func AnalyzeEscalationPaths(clusterRoles []rbacv1.ClusterRole, bindings []rbacv1.ClusterRoleBinding) []Finding {
	var findings []Finding

	for _, cr := range clusterRoles {
		if isSystemResource(cr.Name) {
			continue
		}
		for _, rule := range cr.Rules {
			if canEscalate(rule) {
				findings = append(findings, Finding{
					Resource:    cr.Name,
					Description: fmt.Sprintf("ClusterRole '%s' can create/escalate RBAC bindings", cr.Name),
				})
				break
			}
		}
	}

	return findings
}

// AnalyzeSAPrivileges finds service accounts with cluster-admin-equivalent access.
func AnalyzeSAPrivileges(serviceAccounts []corev1.ServiceAccount, bindings []rbacv1.ClusterRoleBinding) []Finding {
	var findings []Finding

	for _, binding := range bindings {
		if binding.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, subject := range binding.Subjects {
			if subject.Kind == "ServiceAccount" && !isSystemResource(subject.Name) {
				findings = append(findings, Finding{
					Resource:    subject.Name,
					Namespace:   subject.Namespace,
					Description: fmt.Sprintf("ServiceAccount '%s/%s' has cluster-admin via '%s'", subject.Namespace, subject.Name, binding.Name),
				})
			}
		}
	}

	return findings
}

// AnalyzeNamespaceScope finds roles granting cluster-wide access unnecessarily.
func AnalyzeNamespaceScope(roles []rbacv1.Role, roleBindings []rbacv1.RoleBinding) []Finding {
	var findings []Finding

	for _, rb := range roleBindings {
		if rb.RoleRef.Kind == "ClusterRole" && !isSystemResource(rb.RoleRef.Name) {
			findings = append(findings, Finding{
				Resource:    rb.Name,
				Namespace:   rb.Namespace,
				Description: fmt.Sprintf("RoleBinding '%s/%s' references ClusterRole '%s' (consider namespace-scoped Role)", rb.Namespace, rb.Name, rb.RoleRef.Name),
			})
		}
	}

	return findings
}

func hasWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

func canEscalate(rule rbacv1.PolicyRule) bool {
	escalateResources := map[string]bool{
		"clusterrolebindings": true,
		"rolebindings":        true,
		"clusterroles":        true,
		"roles":               true,
	}
	escalateVerbs := map[string]bool{
		"create": true,
		"bind":   true,
		"escalate": true,
		"*":      true,
	}

	hasResource := false
	for _, r := range rule.Resources {
		if escalateResources[r] || r == "*" {
			hasResource = true
			break
		}
	}
	if !hasResource {
		return false
	}

	for _, v := range rule.Verbs {
		if escalateVerbs[v] {
			return true
		}
	}
	return false
}

func isSystemResource(name string) bool {
	return len(name) > 7 && name[:7] == "system:"
}
