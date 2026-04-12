package narrative

import (
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC7_1Raw struct {
	APIServerFound  bool
	AuditLogPath    string
	AuditPolicyFile string
	AuditMaxAge     string
	IsManagedCluster bool
	Findings        []Finding
	PassCount       int
	FailCount       int
}

type CC7_1Narrative struct {
	AuditLoggingSummary string
	ConfigDetails       string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC7_1Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.AuditLoggingSummary, n.ConfigDetails, n.AssessmentStatement} {
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

func BuildCC7_1(raw CC7_1Raw) CC7_1Narrative {
	var n CC7_1Narrative

	if raw.IsManagedCluster {
		n.AuditLoggingSummary = "The organization maintains a continuous audit trail of all cluster infrastructure events to support anomaly detection and forensic analysis. As a managed Kubernetes cluster, audit logging is provided by the cloud provider's control plane, which captures API server requests, authentication events, and authorization decisions. The organization supplements provider-managed audit logging with runtime monitoring of workload configurations and security policy compliance through automated benchmark scanning."
	} else if raw.AuditLogPath != "" {
		n.AuditLoggingSummary = fmt.Sprintf(
			"The organization maintains a continuous audit trail of all cluster infrastructure events to support anomaly detection and forensic analysis. Kubernetes audit logging is enabled on the API server, capturing all API requests including the identity of the actor, the action performed, the resources affected, and the outcome. Audit logs are written to %s.",
			raw.AuditLogPath,
		)
		var configParts []string
		if raw.AuditPolicyFile != "" {
			configParts = append(configParts, fmt.Sprintf("an audit policy file at %s governs which events are recorded and at what verbosity level", raw.AuditPolicyFile))
		}
		if raw.AuditMaxAge != "" {
			configParts = append(configParts, fmt.Sprintf("log retention is configured for %s days to support forensic investigation", raw.AuditMaxAge))
		}
		if len(configParts) > 0 {
			n.ConfigDetails = strings.Join(configParts, ". ") + "."
		}
	} else if raw.APIServerFound {
		n.AuditLoggingSummary = "The API server was identified but audit logging is not configured. Without audit logging, the organization lacks the forensic trail necessary to detect unauthorized access, investigate security incidents, or demonstrate control effectiveness to auditors. This is a significant gap in the monitoring and detection capability."
	} else {
		n.AuditLoggingSummary = "The API server configuration could not be directly inspected. If this is a managed cluster, audit logging may be available through the cloud provider's console and should be enabled to maintain a continuous audit trail of infrastructure events."
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC7_1Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC7_1Raw {
	raw := CC7_1Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	if item := findEvidenceByType(items, "audit-logging"); item != nil {
		if snap, ok := item.Data.(evidence.AuditSnapshot); ok {
			raw.APIServerFound = snap.APIServerFound
			raw.AuditLogPath = snap.AuditLogPath
			raw.AuditPolicyFile = snap.AuditPolicyFile
			raw.AuditMaxAge = snap.AuditMaxAge
			raw.IsManagedCluster = !snap.APIServerFound
		}
	}

	return raw
}
