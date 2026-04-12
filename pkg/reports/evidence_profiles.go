package reports

import "github.com/varax/operator/pkg/evidence"

// controlEvidenceProfiles maps SOC2 control IDs to specific evidence artifact types.
// This provides fine-grained evidence selection per control, replacing the coarse
// category-based mapping in controlEvidenceCategories.
var controlEvidenceProfiles = map[string][]string{
	"CC5.1": {"pss-enforcement", "admission-controllers", "security-context-summary"},
	"CC5.2": {"audit-logging", "pss-labels", "policy-enforcement-status"},
	"CC6.1": {"rbac-cluster-admin", "rbac-sa-token-mount", "auth-config"},
	"CC6.2": {"rbac-sa-inventory", "auth-method", "token-management"},
	"CC6.3": {"rbac-wildcard-roles", "rbac-namespace-scope", "rbac-escalation-paths"},
	"CC6.6": {"network-policy-coverage", "default-deny-status", "ingress-inventory"},
	"CC6.7": {"tls-certificates", "encryption-tls", "in-transit-encryption"},
	"CC6.8": {"pss-enforcement", "privileged-containers", "host-access-summary", "image-policy"},
	"CC7.1": {"audit-logging", "log-retention", "event-monitoring"},
	"CC7.2": {"operator-health", "prometheus-scraping", "scan-schedule"},
	"CC7.3": {"violation-severity-summary", "remediation-priority"},
	"CC7.4": {"audit-logging", "incident-readiness"},
	"CC7.5": {"recovery-controls", "availability-summary"},
	"CC8.1": {"secrets-in-env", "encryption-tls", "image-provenance", "supply-chain-status"},
	"A1.1":  {"resource-quotas", "limit-ranges", "namespace-governance"},
	"A1.2":  {"pdb-coverage", "replica-minimums", "health-probe-coverage", "workload-resilience"},
}

// FilterEvidenceByProfile returns evidence items matching a control's evidence profile.
// It matches on the item's Type field when set, falling back to Category-based matching
// for items that haven't been updated with explicit types.
func FilterEvidenceByProfile(bundle *evidence.EvidenceBundle, controlID string) []evidence.EvidenceItem {
	if bundle == nil {
		return nil
	}

	profiles, hasProfile := controlEvidenceProfiles[controlID]
	if !hasProfile {
		// Fall back to legacy category-based filtering
		return FilterEvidenceForControl(bundle, controlID)
	}

	profileSet := make(map[string]bool, len(profiles))
	for _, p := range profiles {
		profileSet[p] = true
	}

	// Also build the legacy category set for fallback matching
	cats := evidenceCategoriesForControl(controlID)
	catSet := make(map[string]bool, len(cats))
	for _, c := range cats {
		catSet[c] = true
	}

	var filtered []evidence.EvidenceItem
	for _, item := range bundle.Items {
		if item.Type != "" {
			// Prefer type-based matching when Type is set
			if profileSet[item.Type] {
				filtered = append(filtered, item)
			}
		} else if catSet[item.Category] {
			// Fall back to category matching for items without Type
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// EvidenceProfilesForControl returns the evidence artifact types relevant to a control.
func EvidenceProfilesForControl(controlID string) []string {
	return controlEvidenceProfiles[controlID]
}
