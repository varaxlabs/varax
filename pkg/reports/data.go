package reports

import (
	"fmt"
	"time"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

// ReportType identifies which report template to render.
type ReportType string

const (
	ReportTypeReadiness ReportType = "readiness"
	ReportTypeExecutive ReportType = "executive"
)

// ReportFormat identifies the output format.
type ReportFormat string

const (
	FormatHTML ReportFormat = "html"
	FormatJSON ReportFormat = "json"
)

// ReportRequest describes what report to generate.
type ReportRequest struct {
	Type       ReportType
	Format     ReportFormat
	OutputPath string
}

// ReportData is the template context for all report types.
type ReportData struct {
	// Metadata
	ReportTitle  string
	GeneratedAt  time.Time
	VaraxVersion string
	ClusterName  string

	// Compliance results
	Compliance *models.ComplianceResult
	Scan       *models.ScanResult

	// Evidence (optional)
	Evidence *evidence.EvidenceBundle

	// History (optional, for trend analysis)
	HistoricalScores []float64

	// Scan metadata
	ScanDuration         string
	TotalChecks          int
	PassCount            int
	FailCount            int
	WarnCount            int
	SkipCount            int
	ProviderManagedCount int

	// Provider-managed checks for shared responsibility section
	ProviderManagedChecks []models.CheckResult

	// Per-control evidence (populated by generator)
	ControlEvidence map[string][]evidence.EvidenceItem

	// Computed fields populated by the generator
	PassControls    int
	FailControls    int
	PartialControls int
	NAControls      int
	CriticalCount   int
	HighCount       int
	TopFindings     []models.CheckResult
}

// ParseReportType validates and converts a string to ReportType.
func ParseReportType(s string) (ReportType, error) {
	switch ReportType(s) {
	case ReportTypeReadiness:
		return ReportTypeReadiness, nil
	case ReportTypeExecutive:
		return ReportTypeExecutive, nil
	default:
		return "", fmt.Errorf("unsupported report type: %s (use readiness or executive)", s)
	}
}

// ParseReportFormat validates and converts a string to ReportFormat.
func ParseReportFormat(s string) (ReportFormat, error) {
	switch ReportFormat(s) {
	case FormatHTML:
		return FormatHTML, nil
	case FormatJSON:
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("unsupported format: %s (use html or json)", s)
	}
}

// ControlDetail is the template context for per-control evidence pages.
type ControlDetail struct {
	Control  models.ControlResult
	Evidence []evidence.EvidenceItem
}
