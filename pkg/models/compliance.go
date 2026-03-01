package models

// ControlStatus represents the compliance status of a SOC2 control.
type ControlStatus string

const (
	ControlStatusPass        ControlStatus = "PASS"
	ControlStatusFail        ControlStatus = "FAIL"
	ControlStatusPartial     ControlStatus = "PARTIAL"
	ControlStatusNotAssessed ControlStatus = "NOT_ASSESSED"
)

// Control defines a SOC2 Trust Services Criteria control.
type Control struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// ControlMapping links a CIS benchmark check to a SOC2 control.
type ControlMapping struct {
	ControlID string `json:"controlId"`
	CheckIDs  []string `json:"checkIds"`
}

// ControlResult is the evaluated status of a single control.
type ControlResult struct {
	Control        Control       `json:"control"`
	Status         ControlStatus `json:"status"`
	ViolationCount int           `json:"violationCount"`
	CheckResults   []CheckResult `json:"checkResults"`
}

// ComplianceResult contains the full compliance assessment.
type ComplianceResult struct {
	Framework      string          `json:"framework"`
	Score          float64         `json:"score"`
	ControlResults []ControlResult `json:"controlResults"`
}
