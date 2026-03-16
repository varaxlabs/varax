package checks

import "github.com/varax/operator/pkg/scanning"

// RegisterSupplyChain registers supply chain integrity checks with the given registry.
func RegisterSupplyChain(r *scanning.Registry) {
	r.Register(&SBOMAttestationCheck{})
	r.Register(&ImageSignatureCheck{})
	r.Register(&RegistryAllowlistCheck{})
}
