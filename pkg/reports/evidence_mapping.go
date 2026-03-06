package reports

import "github.com/varax/operator/pkg/evidence"

// controlEvidenceCategories maps SOC2 control IDs to relevant evidence categories.
var controlEvidenceCategories = map[string][]string{
	"CC5.1": {"RBAC", "Encryption"},
	"CC5.2": {"RBAC", "Encryption"},
	"CC6.1": {"RBAC"},
	"CC6.2": {"RBAC"},
	"CC6.3": {"RBAC"},
	"CC6.6": {"Network"},
	"CC6.7": {"Network"},
	"CC6.8": {"Encryption"},
	"CC7.1": {"Audit"},
	"CC7.2": {"Audit"},
	"CC7.3": {"Audit"},
	"CC7.4": {"Audit"},
	"CC7.5": {"Audit"},
	"CC8.1": {"Encryption"},
	"A1.1":  {"Network"},
	"A1.2":  {"Network"},
}

// evidenceCategoriesForControl returns the evidence categories relevant to a control.
func evidenceCategoriesForControl(controlID string) []string {
	cats, ok := controlEvidenceCategories[controlID]
	if !ok {
		return nil
	}
	return cats
}

// FilterEvidenceForControl returns evidence items matching a control's categories.
func FilterEvidenceForControl(bundle *evidence.EvidenceBundle, controlID string) []evidence.EvidenceItem {
	if bundle == nil {
		return nil
	}

	cats := evidenceCategoriesForControl(controlID)
	if len(cats) == 0 {
		return nil
	}

	catSet := make(map[string]bool, len(cats))
	for _, c := range cats {
		catSet[c] = true
	}

	var filtered []evidence.EvidenceItem
	for _, item := range bundle.Items {
		if catSet[item.Category] {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
