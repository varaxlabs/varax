package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC7_4Raw struct {
	AuditTrailAvailable bool
	Findings            []Finding
	PassCount           int
	FailCount           int
}

type CC7_4Narrative struct {
	IncidentReadiness   string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC7_4Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.IncidentReadiness, n.AssessmentStatement} {
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

func BuildCC7_4(raw CC7_4Raw) CC7_4Narrative {
	var n CC7_4Narrative

	n.IncidentReadiness = "The organization maintains incident response readiness through continuous audit logging of all Kubernetes API operations, providing the forensic trail necessary to identify, evaluate, and respond to security incidents. Audit records capture the identity of actors, actions performed, resources affected, and timestamps, enabling the incident response team to reconstruct event sequences during investigation. Automated compliance scanning supplements the audit trail by continuously monitoring for configuration drift and security policy violations that may indicate an active incident or attempted compromise."

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC7_4Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC7_4Raw {
	raw := CC7_4Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)
	return raw
}
