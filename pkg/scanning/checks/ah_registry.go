package checks

import "github.com/varax/operator/pkg/scanning"

// RegisterAPIHygiene registers API hygiene checks with the given registry.
func RegisterAPIHygiene(r *scanning.Registry) {
	r.Register(&DeprecatedAPICheck{})
	r.Register(&AlphaBetaAPICheck{})
}
