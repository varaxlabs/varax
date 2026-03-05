package checks

import "github.com/varax/operator/pkg/scanning"

// RegisterRBAC registers RBAC analyzer checks.
func RegisterRBAC(r *scanning.Registry) {
	r.Register(&RBACOverpermissiveCheck{})
	r.Register(&RBACEscalationCheck{})
	r.Register(&RBACSAPrivilegesCheck{})
	r.Register(&RBACNamespaceScopeCheck{})
}
