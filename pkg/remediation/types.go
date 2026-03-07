package remediation

import "time"

// ActionType represents the type of remediation action.
type ActionType string

const (
	ActionPatch  ActionType = "PATCH"
	ActionCreate ActionType = "CREATE"
)

// ActionStatus represents the outcome of a remediation action.
type ActionStatus string

const (
	StatusApplied ActionStatus = "APPLIED"
	StatusDryRun  ActionStatus = "DRY_RUN"
	StatusSkipped ActionStatus = "SKIPPED"
	StatusFailed  ActionStatus = "FAILED"
)

// SkipReason describes why a remediation action was skipped.
type SkipReason string

const (
	SkipSystemNamespace SkipReason = "system-namespace"
	SkipExclusionLabel  SkipReason = "exclusion-label"
	SkipNoRemediator    SkipReason = "no-remediator"
	SkipOwnerNotFound   SkipReason = "owner-not-found"
)

// RemediationAction describes a planned remediation step.
type RemediationAction struct {
	CheckID    string     `json:"checkID"`
	ActionType ActionType `json:"actionType"`
	TargetKind string     `json:"targetKind"`
	TargetName string     `json:"targetName"`
	TargetNS   string     `json:"targetNamespace"`
	Field      string     `json:"field"`
	OldValue   string     `json:"oldValue"`
	NewValue   string     `json:"newValue"`
	PatchJSON  []byte     `json:"-"`
}

// RemediationResult is the outcome of executing a single action.
type RemediationResult struct {
	Action     RemediationAction `json:"action"`
	Status     ActionStatus      `json:"status"`
	SkipReason SkipReason        `json:"skipReason,omitempty"`
	Error      string            `json:"error,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
}

// RemediationPlan collects planned actions from a scan.
type RemediationPlan struct {
	ScanID  string              `json:"scanID"`
	Actions []RemediationAction `json:"actions"`
	DryRun  bool                `json:"dryRun"`
}

// RemediationSummary aggregates counts from a remediation run.
type RemediationSummary struct {
	TotalActions int `json:"totalActions"`
	AppliedCount int `json:"appliedCount"`
	DryRunCount  int `json:"dryRunCount"`
	SkippedCount int `json:"skippedCount"`
	FailedCount  int `json:"failedCount"`
}

// RemediationReport is the full output of a remediation run.
type RemediationReport struct {
	ID        string              `json:"id"`
	ScanID    string              `json:"scanID"`
	Timestamp time.Time           `json:"timestamp"`
	Duration  time.Duration       `json:"duration"`
	DryRun    bool                `json:"dryRun"`
	Results   []RemediationResult `json:"results"`
	Summary   RemediationSummary  `json:"summary"`
}
