package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ComplianceScore = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "varax_compliance_score",
			Help: "Current compliance score (0-100)",
		},
		[]string{"framework", "cluster"},
	)

	ViolationsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "varax_violations_total",
			Help: "Total number of compliance violations",
		},
		[]string{"severity", "framework"},
	)

	ControlStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "varax_control_status",
			Help: "Control compliance status (1=pass, 0=fail, 0.5=partial, -1=not assessed)",
		},
		[]string{"framework", "control"},
	)

	LastScanTimestamp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "varax_last_scan_timestamp",
			Help: "Unix timestamp of the last compliance scan",
		},
	)

	ScanDuration = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "varax_scan_duration_seconds",
			Help: "Duration of the last compliance scan in seconds",
		},
	)

	ChecksTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "varax_checks_total",
			Help: "Total number of compliance checks by status",
		},
		[]string{"status"},
	)

	AuditLoggingEnabled = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "varax_audit_logging_enabled",
			Help: "Whether audit logging is enabled (1=yes, 0=no)",
		},
		[]string{"provider", "cluster"},
	)
)

// RecordControlStatus maps a control status string to its numeric gauge value.
func RecordControlStatus(framework, control, status string) {
	var value float64
	switch status {
	case "PASS":
		value = 1
	case "PARTIAL":
		value = 0.5
	case "FAIL":
		value = 0
	default:
		value = -1
	}
	ControlStatus.WithLabelValues(framework, control).Set(value)
}
