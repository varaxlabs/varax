package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/reports/narrative"
)

// Generator produces compliance reports.
type Generator struct {
	version string
}

// NewGenerator creates a report generator.
func NewGenerator(version string) *Generator {
	return &Generator{version: version}
}

// Generate creates a report and writes it to the specified output path.
func (g *Generator) Generate(req ReportRequest, data *ReportData) error {
	g.populateComputedFields(data)
	data.VaraxVersion = g.version

	switch req.Type {
	case ReportTypeReadiness:
		data.ReportTitle = "SOC2 Readiness Assessment"
	case ReportTypeExecutive:
		data.ReportTitle = "SOC2 Executive Summary"
	default:
		data.ReportTitle = "SOC2 Compliance Report"
	}

	switch req.Format {
	case FormatJSON:
		return g.writeJSON(req.OutputPath, data)
	case FormatHTML:
		return g.writeHTML(req, data)
	case FormatTerminal:
		return g.writeTerminal(req.OutputPath, data)
	default:
		return fmt.Errorf("unsupported format: %s", req.Format)
	}
}

// GenerateControlDetail creates a per-control evidence page.
func (g *Generator) GenerateControlDetail(
	outputPath string,
	format ReportFormat,
	control models.ControlResult,
	evidenceItems []evidence.EvidenceItem,
) error {
	// Build narrative for this control
	evidenceMap := map[string][]evidence.EvidenceItem{control.Control.ID: evidenceItems}
	narratives := narrative.BuildAll([]models.ControlResult{control}, evidenceMap)
	var sections []narrative.NarrativeSection
	if n, ok := narratives[control.Control.ID]; ok && n != nil {
		sections = n.Sections()
	}

	detail := &ControlDetail{
		Control:              control,
		Evidence:             evidenceItems,
		Narrative:            sections,
		VerificationCommands: CommandsForControl(control.Control.ID),
	}

	switch format {
	case FormatJSON:
		return g.writeJSON(outputPath, detail)
	case FormatHTML:
		return renderControlDetailHTML(outputPath, detail, g.version)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func (g *Generator) populateComputedFields(data *ReportData) {
	// Compute assessment period from historical scan times
	if len(data.HistoricalTimes) > 0 {
		data.ScanCount = len(data.HistoricalTimes)
		data.PeriodStart = data.HistoricalTimes[0]
		data.PeriodEnd = data.HistoricalTimes[0]
		for _, t := range data.HistoricalTimes {
			if t.Before(data.PeriodStart) {
				data.PeriodStart = t
			}
			if t.After(data.PeriodEnd) {
				data.PeriodEnd = t
			}
		}
		data.PeriodDays = int(data.PeriodEnd.Sub(data.PeriodStart).Hours()/24) + 1
	} else if data.Scan != nil {
		// Single scan — period is just the scan date
		data.ScanCount = 1
		data.PeriodStart = data.Scan.Timestamp
		data.PeriodEnd = data.Scan.Timestamp
		data.PeriodDays = 1
	}

	// Populate scan metadata
	if data.Scan != nil {
		data.ScanDuration = data.Scan.Duration.Round(time.Millisecond).String()
		data.TotalChecks = data.Scan.Summary.TotalChecks
		data.PassCount = data.Scan.Summary.PassCount
		data.FailCount = data.Scan.Summary.FailCount
		data.WarnCount = data.Scan.Summary.WarnCount
		data.SkipCount = data.Scan.Summary.SkipCount
		data.ProviderManagedCount = data.Scan.Summary.ProviderManagedCount

		// Collect provider-managed checks for the shared responsibility section
		for _, r := range data.Scan.Results {
			if r.Status == models.StatusProviderManaged {
				data.ProviderManagedChecks = append(data.ProviderManagedChecks, r)
			}
		}
	}

	if data.Compliance == nil {
		return
	}

	// Build per-control evidence map using fine-grained profiles
	if data.Evidence != nil {
		data.ControlEvidence = make(map[string][]evidence.EvidenceItem, len(data.Compliance.ControlResults))
		for _, cr := range data.Compliance.ControlResults {
			items := FilterEvidenceByProfile(data.Evidence, cr.Control.ID)
			if len(items) > 0 {
				data.ControlEvidence[cr.Control.ID] = items
			}
		}
	}

	// Build per-control narratives
	data.ControlNarratives = narrative.BuildAll(data.Compliance.ControlResults, data.ControlEvidence)

	// Build per-control verification commands
	data.ControlVerificationCommands = make(map[string][]VerificationCommand, len(data.Compliance.ControlResults))
	for _, cr := range data.Compliance.ControlResults {
		cmds := CommandsForControl(cr.Control.ID)
		if len(cmds) > 0 {
			data.ControlVerificationCommands[cr.Control.ID] = cmds
		}
	}

	// Build per-control structured remediations
	data.ControlRemediations = make(map[string][]RemediationDetail, len(data.Compliance.ControlResults))
	for _, cr := range data.Compliance.ControlResults {
		details := BuildRemediationsForControl(cr)
		if len(details) > 0 {
			data.ControlRemediations[cr.Control.ID] = details
		}
	}

	for _, cr := range data.Compliance.ControlResults {
		switch cr.Status {
		case models.ControlStatusPass:
			data.PassControls++
		case models.ControlStatusFail:
			data.FailControls++
		case models.ControlStatusPartial:
			data.PartialControls++
		case models.ControlStatusNotAssessed:
			data.NAControls++
		}
	}

	if data.Scan != nil {
		var failed []models.CheckResult
		for _, r := range data.Scan.Results {
			if r.Status != models.StatusFail {
				continue
			}
			switch r.Severity {
			case models.SeverityCritical:
				data.CriticalCount++
			case models.SeverityHigh:
				data.HighCount++
			}
			failed = append(failed, r)
		}
		sort.Slice(failed, func(i, j int) bool {
			return severityRank(failed[i].Severity) > severityRank(failed[j].Severity)
		})
		if len(failed) > 10 {
			failed = failed[:10]
		}
		data.TopFindings = failed
	}
}

func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 1
	default:
		return 0
	}
}

func (g *Generator) writeJSON(outputPath string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	if outputPath == "" || outputPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}

	return os.WriteFile(outputPath, data, 0600)
}

func (g *Generator) writeHTML(req ReportRequest, data *ReportData) error {
	switch req.Type {
	case ReportTypeReadiness:
		return renderReadinessHTML(req.OutputPath, data)
	case ReportTypeExecutive:
		return renderExecutiveHTML(req.OutputPath, data)
	default:
		return fmt.Errorf("unsupported report type: %s", req.Type)
	}
}
