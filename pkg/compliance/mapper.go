package compliance

import "github.com/varax/operator/pkg/models"

// Mapper maps scan results to compliance control results.
type Mapper struct {
	controls []models.Control
	mappings []models.ControlMapping
}

// NewSOC2Mapper creates a Mapper configured for SOC2 compliance.
func NewSOC2Mapper() *Mapper {
	return &Mapper{
		controls: SOC2Controls(),
		mappings: SOC2Mappings(),
	}
}

// MapResults takes scan results and produces a full compliance result.
func (m *Mapper) MapResults(scanResult *models.ScanResult) *models.ComplianceResult {
	// Index check results by ID
	checkIndex := make(map[string]models.CheckResult)
	for _, cr := range scanResult.Results {
		checkIndex[cr.ID] = cr
	}

	// Index controls by ID
	controlIndex := make(map[string]models.Control)
	for _, c := range m.controls {
		controlIndex[c.ID] = c
	}

	var controlResults []models.ControlResult
	for _, mapping := range m.mappings {
		control, ok := controlIndex[mapping.ControlID]
		if !ok {
			continue
		}

		cr := models.ControlResult{
			Control: control,
		}

		if len(mapping.CheckIDs) == 0 {
			cr.Status = models.ControlStatusNotAssessed
			controlResults = append(controlResults, cr)
			continue
		}

		var mappedChecks []models.CheckResult
		for _, checkID := range mapping.CheckIDs {
			if result, exists := checkIndex[checkID]; exists {
				mappedChecks = append(mappedChecks, result)
			}
		}

		if len(mappedChecks) == 0 {
			cr.Status = models.ControlStatusNotAssessed
			controlResults = append(controlResults, cr)
			continue
		}

		cr.CheckResults = mappedChecks
		cr.Status = deriveControlStatus(mappedChecks)
		cr.ViolationCount = countViolations(mappedChecks)
		controlResults = append(controlResults, cr)
	}

	scorer := &Scorer{}
	score := scorer.Calculate(controlResults)

	return &models.ComplianceResult{
		Framework:      "SOC2",
		Score:          score,
		ControlResults: controlResults,
	}
}

func deriveControlStatus(checks []models.CheckResult) models.ControlStatus {
	hasPass := false
	hasFail := false

	for _, c := range checks {
		switch c.Status {
		case models.StatusPass, models.StatusProviderManaged:
			hasPass = true
		case models.StatusFail:
			hasFail = true
		}
	}

	switch {
	case hasFail && hasPass:
		return models.ControlStatusPartial
	case hasFail:
		return models.ControlStatusFail
	case hasPass:
		return models.ControlStatusPass
	default:
		return models.ControlStatusNotAssessed
	}
}

func countViolations(checks []models.CheckResult) int {
	count := 0
	for _, c := range checks {
		count += len(c.Evidence)
	}
	return count
}
