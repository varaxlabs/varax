package narrative

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildCC6_7_SelfManaged(t *testing.T) {
	raw := CC6_7Raw{
		EtcdFound:       true,
		CertFileSet:     true,
		ClientCertAuth:  true,
		PeerCertFileSet: true,
		TrustedCASet:    true,
		TLSCertFile:     "/etc/kubernetes/pki/apiserver.crt",
		PassCount:       4,
		FailCount:       0,
	}
	n := BuildCC6_7(raw)
	assert.Contains(t, n.TLSSummary, "/etc/kubernetes/pki/apiserver.crt")
	assert.Contains(t, n.EtcdSummary, "server certificates")
	assert.Contains(t, n.EtcdSummary, "mutual TLS")
	assert.Contains(t, n.EtcdSummary, "peer TLS")
	assert.Contains(t, n.EtcdSummary, "certificate authority")
	assert.Contains(t, n.AssessmentStatement, "PASS")
}

func TestBuildCC6_7_Managed(t *testing.T) {
	raw := CC6_7Raw{
		EtcdFound: false,
		PassCount: 2,
		FailCount: 0,
	}
	n := BuildCC6_7(raw)
	assert.Contains(t, n.TLSSummary, "managed cluster")
	assert.Contains(t, n.EtcdSummary, "managed by the cloud provider")
	assert.Contains(t, n.AssessmentStatement, "PASS")
}

func TestBuildCC6_7_EtcdNoTLS(t *testing.T) {
	raw := CC6_7Raw{
		EtcdFound:   true,
		TLSCertFile: "/etc/kubernetes/pki/apiserver.crt",
		PassCount:   1,
		FailCount:   2,
	}
	n := BuildCC6_7(raw)
	assert.Contains(t, n.EtcdSummary, "no TLS configuration was detected")
	assert.Contains(t, n.AssessmentStatement, "PARTIAL")
}

func TestBuildCC6_7_PartialEtcdProtections(t *testing.T) {
	raw := CC6_7Raw{
		EtcdFound:      true,
		CertFileSet:    true,
		ClientCertAuth: true,
		TLSCertFile:    "/etc/kubernetes/pki/apiserver.crt",
		PassCount:      3,
		FailCount:      1,
	}
	n := BuildCC6_7(raw)
	assert.Contains(t, n.EtcdSummary, "server certificates")
	assert.Contains(t, n.EtcdSummary, "mutual TLS")
	assert.NotContains(t, n.EtcdSummary, "peer TLS")
}

func TestBuildCC6_7_WithFindings(t *testing.T) {
	raw := CC6_7Raw{
		PassCount: 1,
		FailCount: 1,
		Findings: []Finding{
			{CheckID: "CIS-2.1", Severity: "HIGH", Message: "etcd cert missing"},
		},
	}
	n := BuildCC6_7(raw)
	assert.Len(t, n.Findings, 1)
}

func TestCC6_7Narrative_Sections(t *testing.T) {
	raw := CC6_7Raw{
		EtcdFound:   true,
		CertFileSet: true,
		TLSCertFile: "/etc/kubernetes/pki/apiserver.crt",
		PassCount:   2,
		FailCount:   1,
		Findings: []Finding{
			{CheckID: "CIS-2.1", Severity: "HIGH", Message: "test"},
		},
	}
	n := BuildCC6_7(raw)
	sections := n.Sections()
	assert.GreaterOrEqual(t, len(sections), 3)
}
