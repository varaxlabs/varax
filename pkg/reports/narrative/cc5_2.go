package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC5_2Raw struct {
	AuditPolicyConfigured bool
	AuditLogPath          string
	Findings              []Finding
	PassCount             int
	FailCount             int
}

type CC5_2Narrative struct {
	PolicySummary       string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC5_2Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.PolicySummary, n.AssessmentStatement} {
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

func BuildCC5_2(raw CC5_2Raw) CC5_2Narrative {
	var n CC5_2Narrative

	if raw.AuditPolicyConfigured {
		n.PolicySummary = fmt.Sprintf(
			"The organization deploys control activities through documented policies enforced by Kubernetes audit logging and Pod Security Standards. An audit policy governs which API operations are recorded and at what level of detail, with audit logs written to %s. Pod Security Standards establish the expected security posture for workloads, and admission controllers enforce these standards as automated procedures at deployment time.",
			raw.AuditLogPath,
		)
	} else {
		n.PolicySummary = "The organization deploys control activities through Pod Security Standards, which establish the expected security posture for workloads and are enforced by admission controllers at deployment time. Audit policy configuration should be reviewed to ensure comprehensive logging of security-relevant API operations, as this provides the procedural record of control enforcement."
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC5_2Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC5_2Raw {
	raw := CC5_2Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	if item := findEvidenceByType(items, "audit-logging"); item != nil {
		if snap, ok := item.Data.(evidence.AuditSnapshot); ok {
			raw.AuditPolicyConfigured = snap.AuditPolicyFile != ""
			raw.AuditLogPath = snap.AuditLogPath
		}
	}

	return raw
}
