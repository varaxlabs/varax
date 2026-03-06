package reports

import (
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

	// Computed fields populated by the generator
	PassControls    int
	FailControls    int
	PartialControls int
	NAControls      int
	CriticalCount   int
	HighCount       int
	TopFindings     []models.CheckResult
}

// ControlDetail is the template context for per-control evidence pages.
type ControlDetail struct {
	Control  models.ControlResult
	Evidence []evidence.EvidenceItem
}
