package models

import "time"

// Severity represents the severity level of a compliance check finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// CheckStatus represents the result status of a compliance check.
type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusFail CheckStatus = "FAIL"
	StatusWarn CheckStatus = "WARN"
	StatusSkip CheckStatus = "SKIP"
)

// Resource identifies a Kubernetes resource involved in a check result.
type Resource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Evidence provides detail about why a check produced its result.
type Evidence struct {
	Message  string   `json:"message"`
	Resource Resource `json:"resource"`
	Field    string   `json:"field,omitempty"`
	Value    string   `json:"value,omitempty"`
}

// CheckResult is the outcome of running a single compliance check.
type CheckResult struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Benchmark   string      `json:"benchmark"`
	Section     string      `json:"section"`
	Severity    Severity    `json:"severity"`
	Status      CheckStatus `json:"status"`
	Evidence    []Evidence  `json:"evidence,omitempty"`
	Message     string      `json:"message"`
}

// ScanSummary aggregates counts from a scan run.
type ScanSummary struct {
	TotalChecks int `json:"totalChecks"`
	PassCount   int `json:"passCount"`
	FailCount   int `json:"failCount"`
	WarnCount   int `json:"warnCount"`
	SkipCount   int `json:"skipCount"`
}

// ScanResult contains all results from a single scan run.
type ScanResult struct {
	ID        string        `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
	Results   []CheckResult `json:"results"`
	Summary   ScanSummary   `json:"summary"`
}
