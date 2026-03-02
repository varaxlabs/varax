package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComplianceConfigSpec defines the desired state of ComplianceConfig.
type ComplianceConfigSpec struct {
	// Framework specifies the compliance framework (e.g., "SOC2").
	// +kubebuilder:validation:Enum=SOC2
	// +kubebuilder:default=SOC2
	Framework string `json:"framework"`

	// Controls configures which controls to evaluate.
	// +optional
	Controls ControlsSpec `json:"controls,omitempty"`

	// Scanning configures scanning behavior.
	// +optional
	Scanning ScanningSpec `json:"scanning,omitempty"`

	// AuditLogging configures audit log collection.
	// +optional
	AuditLogging AuditLoggingSpec `json:"auditLogging,omitempty"`

	// Remediation configures automatic remediation behavior.
	// +optional
	Remediation RemediationSpec `json:"remediation,omitempty"`

	// Reports configures report generation.
	// +optional
	Reports ReportsSpec `json:"reports,omitempty"`

	// Alerts configures alerting thresholds and destinations.
	// +optional
	Alerts AlertsSpec `json:"alerts,omitempty"`
}

// ControlsSpec defines which controls to include or exclude.
type ControlsSpec struct {
	// Enabled lists control IDs to evaluate. Empty means all.
	// +optional
	Enabled []string `json:"enabled,omitempty"`

	// Disabled lists control IDs to skip.
	// +optional
	Disabled []string `json:"disabled,omitempty"`
}

// ScanningSpec configures scanning behavior.
type ScanningSpec struct {
	// Interval is the time between scans (e.g., "5m", "1h").
	// +kubebuilder:default="5m"
	// +kubebuilder:validation:Pattern=`^[0-9]+(s|m|h)$`
	Interval string `json:"interval,omitempty"`

	// ExcludeNamespaces lists namespaces to skip during scanning.
	// +optional
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
}

// AuditLoggingSpec configures audit log collection.
type AuditLoggingSpec struct {
	// Enabled controls whether audit log collection is active.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
}

// RemediationSpec configures automatic remediation.
type RemediationSpec struct {
	// AutoRemediate enables automatic remediation of violations.
	// +kubebuilder:default=false
	AutoRemediate bool `json:"autoRemediate,omitempty"`

	// DryRun logs remediation actions without applying them.
	// +kubebuilder:default=true
	DryRun bool `json:"dryRun,omitempty"`
}

// ReportsSpec configures report generation.
type ReportsSpec struct {
	// Formats specifies output formats (e.g., ["json", "pdf"]).
	// +optional
	Formats []string `json:"formats,omitempty"`

	// Schedule is a cron expression for report generation.
	// +optional
	Schedule string `json:"schedule,omitempty"`
}

// AlertsSpec configures alerting.
type AlertsSpec struct {
	// ScoreThreshold triggers an alert when the compliance score drops below this value.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	ScoreThreshold *int `json:"scoreThreshold,omitempty"`

	// CriticalViolations triggers an alert when critical violation count exceeds this value.
	// +kubebuilder:validation:Minimum=0
	// +optional
	CriticalViolations *int `json:"criticalViolations,omitempty"`
}

// CompliancePhase describes the current phase of the compliance operator.
type CompliancePhase string

const (
	PhaseScanning   CompliancePhase = "Scanning"
	PhaseCompliant  CompliancePhase = "Compliant"
	PhaseViolations CompliancePhase = "Violations"
	PhaseError      CompliancePhase = "Error"
)

// FrameworkStatus summarizes compliance status for a framework.
type FrameworkStatus struct {
	// Name is the framework name.
	Name string `json:"name"`

	// Score is the compliance score (0-100).
	Score int `json:"score"`

	// PassingControls is the number of passing controls.
	PassingControls int `json:"passingControls"`

	// TotalControls is the total number of assessed controls.
	TotalControls int `json:"totalControls"`
}

// ComplianceConfigStatus defines the observed state of ComplianceConfig.
type ComplianceConfigStatus struct {
	// Phase is the current phase of the compliance operator.
	// +optional
	Phase CompliancePhase `json:"phase,omitempty"`

	// LastScanTime is the timestamp of the last scan.
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// ComplianceScore is the overall compliance score (0-100).
	// +optional
	ComplianceScore int `json:"complianceScore,omitempty"`

	// ViolationCount is the total number of violations found.
	// +optional
	ViolationCount int `json:"violationCount,omitempty"`

	// FrameworkStatus contains per-framework status summaries.
	// +optional
	FrameworkStatus []FrameworkStatus `json:"frameworkStatus,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Framework",type=string,JSONPath=`.spec.framework`
// +kubebuilder:printcolumn:name="Score",type=integer,JSONPath=`.status.complianceScore`
// +kubebuilder:printcolumn:name="Violations",type=integer,JSONPath=`.status.violationCount`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ComplianceConfig is the Schema for the complianceconfigs API.
type ComplianceConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ComplianceConfigSpec   `json:"spec,omitempty"`
	Status ComplianceConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ComplianceConfigList contains a list of ComplianceConfig.
type ComplianceConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceConfig{}, &ComplianceConfigList{})
}
