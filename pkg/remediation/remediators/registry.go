package remediators

import "github.com/varax/operator/pkg/remediation"

// RegisterAll registers all built-in remediators.
func RegisterAll(reg *remediation.RemediatorRegistry) {
	// Security context remediators (CIS 5.2.x)
	reg.Register(&PrivilegeEscalationRemediator{})
	reg.Register(&RunAsNonRootRemediator{})
	reg.Register(&PrivilegedRemediator{})
	reg.Register(&DropCapabilitiesRemediator{})
	reg.Register(&SeccompRemediator{})

	// Pod spec remediators (CIS 5.2.5-5.2.7)
	reg.Register(&HostPIDRemediator{})
	reg.Register(&HostIPCRemediator{})
	reg.Register(&HostNetworkRemediator{})

	// ServiceAccount remediator (CIS 5.1.6)
	reg.Register(&SATokenRemediator{})

	// NetworkPolicy remediator (CIS 5.3.2)
	reg.Register(&NetworkPolicyRemediator{})

	// LimitRange remediator (CIS 5.7.1)
	reg.Register(&LimitRangeRemediator{})
}
