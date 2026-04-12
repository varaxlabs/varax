package narrative

import (
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC6_7Raw struct {
	EtcdFound       bool
	CertFileSet     bool
	ClientCertAuth  bool
	PeerCertFileSet bool
	TrustedCASet    bool
	TLSCertFile     string
	Findings        []Finding
	PassCount       int
	FailCount       int
}

type CC6_7Narrative struct {
	TLSSummary          string
	EtcdSummary         string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC6_7Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.TLSSummary, n.EtcdSummary, n.AssessmentStatement} {
		if body != "" {
			sections = append(sections, NarrativeSection{Body: body})
		}
	}
	if s := findingsSection(n.Findings); len(s.Items) > 0 {
		// Insert findings before the assessment (which is the last element)
		if len(sections) > 0 {
			last := sections[len(sections)-1]
			sections[len(sections)-1] = s
			sections = append(sections, last)
		} else {
			sections = append(sections, s)
		}
	}
	return sections
}

func BuildCC6_7(raw CC6_7Raw) CC6_7Narrative {
	var n CC6_7Narrative

	if raw.TLSCertFile != "" {
		n.TLSSummary = fmt.Sprintf(
			"The organization restricts data transmission through TLS encryption on all Kubernetes API communications. The API server is configured with a TLS certificate at %s, ensuring that all client-to-cluster communication is encrypted in transit. This protects authentication credentials, configuration data, and workload specifications from interception.",
			raw.TLSCertFile,
		)
	} else {
		n.TLSSummary = "The organization restricts data transmission through encrypted channels for all Kubernetes API communications. As a managed cluster, TLS termination and certificate management for the API server are handled by the cloud provider, ensuring encrypted communication between clients and the control plane."
	}

	if raw.EtcdFound {
		var etcdProtections []string
		if raw.CertFileSet {
			etcdProtections = append(etcdProtections, "server certificates for client connections")
		}
		if raw.ClientCertAuth {
			etcdProtections = append(etcdProtections, "mutual TLS (mTLS) client certificate authentication")
		}
		if raw.PeerCertFileSet {
			etcdProtections = append(etcdProtections, "peer TLS for etcd cluster replication")
		}
		if raw.TrustedCASet {
			etcdProtections = append(etcdProtections, "certificate authority validation")
		}
		if len(etcdProtections) > 0 {
			n.EtcdSummary = "The cluster's persistent data store (etcd), which holds all Kubernetes state including secrets, is protected with: " + strings.Join(etcdProtections, ", ") + "."
		} else {
			n.EtcdSummary = "The etcd data store was identified but no TLS configuration was detected. Without encryption in transit, cluster state data including secrets may be exposed on the network."
		}
	} else {
		n.EtcdSummary = "The etcd data store is managed by the cloud provider and is not directly accessible. Encryption in transit for the data store is an inherited control from the provider's infrastructure."
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC6_7Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC6_7Raw {
	raw := CC6_7Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	if item := findEvidenceByType(items, "encryption-tls"); item != nil {
		if snap, ok := item.Data.(evidence.EncryptionSnapshot); ok {
			raw.EtcdFound = snap.EtcdFound
			raw.CertFileSet = snap.CertFileSet
			raw.ClientCertAuth = snap.ClientCertAuth
			raw.PeerCertFileSet = snap.PeerCertFileSet
			raw.TrustedCASet = snap.TrustedCASet
			raw.TLSCertFile = snap.TLSCertFile
		}
	}

	return raw
}
