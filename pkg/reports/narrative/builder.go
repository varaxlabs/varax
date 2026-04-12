package narrative

import (
	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

// BuildAll generates narratives for all controls that have mapped check results.
// Returns a map of control ID to ControlNarrative.
func BuildAll(
	controls []models.ControlResult,
	evidenceMap map[string][]evidence.EvidenceItem,
) map[string]ControlNarrative {
	result := make(map[string]ControlNarrative, len(controls))

	for _, cr := range controls {
		if cr.Status == models.ControlStatusNotAssessed {
			continue
		}
		var items []evidence.EvidenceItem
		if evidenceMap != nil {
			items = evidenceMap[cr.Control.ID]
		}
		if n := buildForControl(cr, items); n != nil {
			result[cr.Control.ID] = n
		}
	}

	return result
}

// buildForControl dispatches to the per-control narrative builder.
func buildForControl(cr models.ControlResult, items []evidence.EvidenceItem) ControlNarrative {
	switch cr.Control.ID {
	case "CC5.1":
		return BuildCC5_1(extractCC5_1Raw(cr, items))
	case "CC5.2":
		return BuildCC5_2(extractCC5_2Raw(cr, items))
	case "CC6.1":
		return BuildCC6_1(extractCC6_1Raw(cr, items))
	case "CC6.2":
		return BuildCC6_2(extractCC6_2Raw(cr, items))
	case "CC6.3":
		return BuildCC6_3(extractCC6_3Raw(cr, items))
	case "CC6.6":
		return BuildCC6_6(extractCC6_6Raw(cr, items))
	case "CC6.7":
		return BuildCC6_7(extractCC6_7Raw(cr, items))
	case "CC6.8":
		return BuildCC6_8(extractCC6_8Raw(cr, items))
	case "CC7.1":
		return BuildCC7_1(extractCC7_1Raw(cr, items))
	case "CC7.2":
		return BuildCC7_2(extractCC7_2Raw(cr, items))
	case "CC7.3":
		return BuildCC7_3(extractCC7_3Raw(cr, items))
	case "CC7.4":
		return BuildCC7_4(extractCC7_4Raw(cr, items))
	case "CC7.5":
		return BuildCC7_5(extractCC7_5Raw(cr, items))
	case "CC8.1":
		return BuildCC8_1(extractCC8_1Raw(cr, items))
	case "A1.1":
		return BuildA1_1(extractA1_1Raw(cr, items))
	case "A1.2":
		return BuildA1_2(extractA1_2Raw(cr, items))
	default:
		return nil
	}
}

// countCheckStatus counts passing and failing checks in a control result.
func countCheckStatus(cr models.ControlResult) (pass, fail int) {
	for _, c := range cr.CheckResults {
		switch c.Status {
		case models.StatusPass, models.StatusProviderManaged:
			pass++
		case models.StatusFail:
			fail++
		}
	}
	return
}

// extractFindings extracts findings from failing check results.
func extractFindings(cr models.ControlResult) []Finding {
	var findings []Finding
	for _, c := range cr.CheckResults {
		if c.Status == models.StatusFail {
			findings = append(findings, Finding{
				CheckID:  c.ID,
				Severity: string(c.Severity),
				Message:  c.Message,
			})
		}
	}
	return findings
}

// findEvidenceByType returns the first evidence item matching the given type.
func findEvidenceByType(items []evidence.EvidenceItem, typ string) *evidence.EvidenceItem {
	for i := range items {
		if items[i].Type == typ {
			return &items[i]
		}
	}
	return nil
}
