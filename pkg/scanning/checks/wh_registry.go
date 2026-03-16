package checks

import "github.com/varax/operator/pkg/scanning"

// RegisterWorkloadHygiene registers workload hygiene checks with the given registry.
func RegisterWorkloadHygiene(r *scanning.Registry) {
	r.Register(&ImageTagPolicyCheck{})
	r.Register(&ResourceLimitsCheck{})
	r.Register(&HealthProbesCheck{})
	r.Register(&ReplicaMinimumsCheck{})
	r.Register(&PDBCoverageCheck{})
}
