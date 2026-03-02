package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestComplianceConfig_DeepCopy(t *testing.T) {
	threshold := 70
	criticals := 5

	original := &ComplianceConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "compliance.varax.io/v1alpha1",
			Kind:       "ComplianceConfig",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: ComplianceConfigSpec{
			Framework: "SOC2",
			Controls: ControlsSpec{
				Enabled:  []string{"CC6.1", "CC6.2"},
				Disabled: []string{"CC8.1"},
			},
			Scanning: ScanningSpec{
				Interval:          "5m",
				ExcludeNamespaces: []string{"kube-system"},
			},
			AuditLogging: AuditLoggingSpec{
				Enabled: true,
			},
			Remediation: RemediationSpec{
				AutoRemediate: false,
				DryRun:        true,
			},
			Reports: ReportsSpec{
				Formats:  []string{"json", "pdf"},
				Schedule: "0 0 * * 0",
			},
			Alerts: AlertsSpec{
				ScoreThreshold:     &threshold,
				CriticalViolations: &criticals,
			},
		},
		Status: ComplianceConfigStatus{
			Phase:           PhaseCompliant,
			ComplianceScore: 85,
			ViolationCount:  3,
			FrameworkStatus: []FrameworkStatus{
				{Name: "SOC2", Score: 85, PassingControls: 7, TotalControls: 9},
			},
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Scanned"},
			},
		},
	}

	copied := original.DeepCopy()
	require.NotNil(t, copied)

	// Verify it's a distinct object
	assert.Equal(t, original.Spec.Framework, copied.Spec.Framework)
	assert.Equal(t, original.Spec.Controls.Enabled, copied.Spec.Controls.Enabled)
	assert.Equal(t, original.Spec.Alerts.ScoreThreshold, copied.Spec.Alerts.ScoreThreshold)

	// Modify original to prove deep copy independence
	original.Spec.Controls.Enabled[0] = "CHANGED"
	assert.NotEqual(t, original.Spec.Controls.Enabled[0], copied.Spec.Controls.Enabled[0])

	*original.Spec.Alerts.ScoreThreshold = 999
	assert.Equal(t, 70, *copied.Spec.Alerts.ScoreThreshold)
}

func TestComplianceConfig_DeepCopyObject(t *testing.T) {
	original := &ComplianceConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       ComplianceConfigSpec{Framework: "SOC2"},
	}

	var obj runtime.Object = original
	copied := obj.DeepCopyObject()
	require.NotNil(t, copied)

	cc, ok := copied.(*ComplianceConfig)
	require.True(t, ok)
	assert.Equal(t, "SOC2", cc.Spec.Framework)
}

func TestComplianceConfigList_DeepCopy(t *testing.T) {
	list := &ComplianceConfigList{
		Items: []ComplianceConfig{
			{ObjectMeta: metav1.ObjectMeta{Name: "one"}, Spec: ComplianceConfigSpec{Framework: "SOC2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "two"}, Spec: ComplianceConfigSpec{Framework: "SOC2"}},
		},
	}

	copied := list.DeepCopy()
	require.NotNil(t, copied)
	assert.Len(t, copied.Items, 2)
	assert.Equal(t, "one", copied.Items[0].Name)

	// Modify original
	list.Items[0].Name = "CHANGED"
	assert.Equal(t, "one", copied.Items[0].Name)
}

func TestComplianceConfigList_DeepCopyObject(t *testing.T) {
	list := &ComplianceConfigList{
		Items: []ComplianceConfig{
			{ObjectMeta: metav1.ObjectMeta{Name: "one"}},
		},
	}

	var obj runtime.Object = list
	copied := obj.DeepCopyObject()
	require.NotNil(t, copied)

	ccl, ok := copied.(*ComplianceConfigList)
	require.True(t, ok)
	assert.Len(t, ccl.Items, 1)
}

func TestAlertSpec_DeepCopy_NilPointers(t *testing.T) {
	original := &AlertsSpec{}
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.Nil(t, copied.ScoreThreshold)
	assert.Nil(t, copied.CriticalViolations)
}

func TestScanningSpec_DeepCopy(t *testing.T) {
	original := &ScanningSpec{
		Interval:          "10m",
		ExcludeNamespaces: []string{"ns1", "ns2"},
	}
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.Equal(t, "10m", copied.Interval)
	assert.Equal(t, []string{"ns1", "ns2"}, copied.ExcludeNamespaces)

	original.ExcludeNamespaces[0] = "CHANGED"
	assert.Equal(t, "ns1", copied.ExcludeNamespaces[0])
}

func TestReportsSpec_DeepCopy(t *testing.T) {
	original := &ReportsSpec{
		Formats:  []string{"json", "html"},
		Schedule: "0 * * * *",
	}
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.Equal(t, []string{"json", "html"}, copied.Formats)

	original.Formats[0] = "CHANGED"
	assert.Equal(t, "json", copied.Formats[0])
}

func TestFrameworkStatus_DeepCopy(t *testing.T) {
	original := &FrameworkStatus{
		Name:            "SOC2",
		Score:           85,
		PassingControls: 7,
		TotalControls:   9,
	}
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.Equal(t, "SOC2", copied.Name)
	assert.Equal(t, 85, copied.Score)
}

func TestDeepCopy_NilReceivers(t *testing.T) {
	var alerts *AlertsSpec
	assert.Nil(t, alerts.DeepCopy())

	var audit *AuditLoggingSpec
	assert.Nil(t, audit.DeepCopy())

	var cc *ComplianceConfig
	assert.Nil(t, cc.DeepCopy())

	var ccList *ComplianceConfigList
	assert.Nil(t, ccList.DeepCopy())

	var spec *ComplianceConfigSpec
	assert.Nil(t, spec.DeepCopy())

	var status *ComplianceConfigStatus
	assert.Nil(t, status.DeepCopy())

	var controls *ControlsSpec
	assert.Nil(t, controls.DeepCopy())

	var fw *FrameworkStatus
	assert.Nil(t, fw.DeepCopy())

	var rem *RemediationSpec
	assert.Nil(t, rem.DeepCopy())

	var reports *ReportsSpec
	assert.Nil(t, reports.DeepCopy())

	var scanning *ScanningSpec
	assert.Nil(t, scanning.DeepCopy())
}

func TestControlsSpec_DeepCopy(t *testing.T) {
	original := &ControlsSpec{
		Enabled:  []string{"CC6.1"},
		Disabled: []string{"CC8.1"},
	}
	copied := original.DeepCopy()
	require.NotNil(t, copied)

	original.Enabled[0] = "CHANGED"
	original.Disabled[0] = "CHANGED"
	assert.Equal(t, "CC6.1", copied.Enabled[0])
	assert.Equal(t, "CC8.1", copied.Disabled[0])
}

func TestRemediationSpec_DeepCopy(t *testing.T) {
	original := &RemediationSpec{AutoRemediate: true, DryRun: false}
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.True(t, copied.AutoRemediate)
	assert.False(t, copied.DryRun)
}

func TestAuditLoggingSpec_DeepCopy(t *testing.T) {
	original := &AuditLoggingSpec{Enabled: true}
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.True(t, copied.Enabled)
}

func TestComplianceConfigStatus_DeepCopy_WithLastScanTime(t *testing.T) {
	now := metav1.Now()
	original := &ComplianceConfigStatus{
		Phase:           PhaseCompliant,
		LastScanTime:    &now,
		ComplianceScore: 90,
		ViolationCount:  0,
		FrameworkStatus: []FrameworkStatus{{Name: "SOC2", Score: 90}},
		Conditions:      []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
	}
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	require.NotNil(t, copied.LastScanTime)
	assert.Equal(t, 90, copied.ComplianceScore)
}

func TestSchemeRegistration(t *testing.T) {
	s := runtime.NewScheme()
	err := AddToScheme(s)
	require.NoError(t, err)

	// Verify the types are registered
	gvk := GroupVersion.WithKind("ComplianceConfig")
	obj, err := s.New(gvk)
	require.NoError(t, err)
	assert.NotNil(t, obj)
}
