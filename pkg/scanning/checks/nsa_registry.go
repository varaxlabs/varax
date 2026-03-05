package checks

import "github.com/varax/operator/pkg/scanning"

// RegisterNSACISA registers all NSA/CISA hardening guide checks.
func RegisterNSACISA(r *scanning.Registry) {
	// Delegating checks (wrap CIS checks)
	r.Register(NSAPS1)
	r.Register(NSAPS2)
	r.Register(NSAPS3)
	r.Register(NSAPS4)
	r.Register(NSAPS5)
	r.Register(NSAPS6)
	r.Register(NSANS1)
	r.Register(NSAAA1)
	r.Register(NSAAA2)
	r.Register(NSAAA3)
	r.Register(NSAAA4)
	r.Register(NSALM1)
	r.Register(NSALM2)
	r.Register(NSASC1)
	r.Register(NSASC2)

	// Unique NSA/CISA checks
	r.Register(&NSAImmutableFSCheck{})
	r.Register(&NSAResourceLimitsCheck{})
	r.Register(&NSADefaultDenyIngressCheck{})
	r.Register(&NSADefaultDenyEgressCheck{})
	r.Register(&NSAAnonAuthCheck{})
	r.Register(&NSAImagePullPolicyCheck{})
}
