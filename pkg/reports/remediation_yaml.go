package reports

import (
	"fmt"

	"github.com/varax/operator/pkg/models"
)

// RemediationDetail provides structured remediation data for a single failing check,
// including the text guidance plus dry-run and export commands.
type RemediationDetail struct {
	CheckID     string `json:"checkId"`
	CheckName   string `json:"checkName"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	DryRunCmd   string `json:"dryRunCmd,omitempty"`
}

// BuildRemediationsForControl extracts remediation details for all failing checks in a control.
func BuildRemediationsForControl(cr models.ControlResult) []RemediationDetail {
	var details []RemediationDetail
	for _, c := range cr.CheckResults {
		if c.Status != models.StatusFail {
			continue
		}
		guidance := Remediation(c.ID)
		if guidance == "" {
			continue
		}
		details = append(details, RemediationDetail{
			CheckID:     c.ID,
			CheckName:   c.Name,
			Severity:    string(c.Severity),
			Description: guidance,
			DryRunCmd:   fmt.Sprintf("varax remediate --check %s --dry-run", c.ID),
		})
	}
	return details
}
