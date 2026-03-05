package checks

import "github.com/varax/operator/pkg/scanning"

// RegisterPSS registers Pod Security Standards checks.
func RegisterPSS(r *scanning.Registry) {
	r.Register(&PSSEnforceLabelCheck{})
	r.Register(&PSSBaselineEnforceCheck{})
	r.Register(&PSSRestrictedEnforceCheck{})
	r.Register(&PSSAuditLabelCheck{})
	r.Register(&PSSWarnLabelCheck{})
}
