package checks

import "github.com/kubeshield/operator/pkg/scanning"

// RegisterAll registers all built-in checks with the given registry.
func RegisterAll(r *scanning.Registry) {
	// RBAC checks (5.1.x)
	r.Register(&ClusterAdminCheck{})
	r.Register(&SecretAccessCheck{})
	r.Register(&WildcardRBACCheck{})
	r.Register(&DefaultServiceAccountCheck{})
	r.Register(&SATokenAutoMountCheck{})
	r.Register(&EscalatePermsCheck{})

	// Pod security checks (5.2.x)
	r.Register(&PrivilegeEscalationCheck{})
	r.Register(&RootContainerCheck{})
	r.Register(&PrivilegedContainerCheck{})
	r.Register(&DropCapabilitiesCheck{})
	r.Register(&HostPIDCheck{})
	r.Register(&HostIPCCheck{})
	r.Register(&HostNetworkCheck{})
	r.Register(&HostPortCheck{})
	r.Register(&AddedCapabilitiesCheck{})

	// Network policy checks (5.3.x)
	r.Register(&NetworkPolicyCheck{})

	// Secret management checks (5.4.x)
	r.Register(&SecretEnvVarCheck{})

	// General security checks (5.7.x)
	r.Register(&SeccompCheck{})
	r.Register(&SecurityContextCheck{})
	r.Register(&DefaultNamespaceCheck{})
}
