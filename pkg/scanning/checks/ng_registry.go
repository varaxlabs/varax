package checks

import "github.com/varax/operator/pkg/scanning"

// RegisterNamespaceGov registers namespace governance checks with the given registry.
func RegisterNamespaceGov(r *scanning.Registry) {
	r.Register(&ResourceQuotaCheck{})
	r.Register(&LimitRangeCheck{})
	r.Register(&LabelStandardsCheck{})
}
