package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getGaugeValue(gauge prometheus.Gauge) float64 {
	var m dto.Metric
	_ = gauge.Write(&m)
	return *m.Gauge.Value
}

func TestRecordControlStatus_Pass(t *testing.T) {
	RecordControlStatus("SOC2", "CC6.1", "PASS")
	val := getGaugeValue(ControlStatus.WithLabelValues("SOC2", "CC6.1"))
	assert.Equal(t, float64(1), val)
}

func TestRecordControlStatus_Fail(t *testing.T) {
	RecordControlStatus("SOC2", "CC6.2", "FAIL")
	val := getGaugeValue(ControlStatus.WithLabelValues("SOC2", "CC6.2"))
	assert.Equal(t, float64(0), val)
}

func TestRecordControlStatus_Partial(t *testing.T) {
	RecordControlStatus("SOC2", "CC6.3", "PARTIAL")
	val := getGaugeValue(ControlStatus.WithLabelValues("SOC2", "CC6.3"))
	assert.Equal(t, float64(0.5), val)
}

func TestRecordControlStatus_NotAssessed(t *testing.T) {
	RecordControlStatus("SOC2", "CC7.1", "NOT_ASSESSED")
	val := getGaugeValue(ControlStatus.WithLabelValues("SOC2", "CC7.1"))
	assert.Equal(t, float64(-1), val)
}

func TestMetricsRegistered(t *testing.T) {
	// Verify all metrics can be used without panicking
	require.NotPanics(t, func() {
		ComplianceScore.WithLabelValues("SOC2", "test").Set(85)
		ViolationsTotal.WithLabelValues("CRITICAL", "SOC2").Set(3)
		LastScanTimestamp.Set(1234567890)
		ScanDuration.Set(5.5)
		ChecksTotal.WithLabelValues("pass").Set(10)
		AuditLoggingEnabled.WithLabelValues("EKS", "test").Set(1)
	})
}
