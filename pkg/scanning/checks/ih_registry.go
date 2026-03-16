package checks

import "github.com/varax/operator/pkg/scanning"

// RegisterIngressHardening registers ingress hardening checks with the given registry.
func RegisterIngressHardening(r *scanning.Registry) {
	r.Register(&TLSIngressCheck{})
	r.Register(&EgressPolicyCheck{})
}
