package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC7_3Raw struct {
	Findings  []Finding
	PassCount int
	FailCount int
}

type CC7_3Narrative struct {
	EvaluationSummary   string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC7_3Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.EvaluationSummary, n.AssessmentStatement} {
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

func BuildCC7_3(raw CC7_3Raw) CC7_3Narrative {
	var n CC7_3Narrative

	n.EvaluationSummary = "The organization evaluates detected security events to determine whether they could result in a failure to meet its security objectives. Automated compliance scanning provides a centralized security dashboard with findings aggregated by severity, enabling the security team to prioritize investigation and response. Each finding includes the specific resource, namespace, and configuration detail that triggered the detection, supporting rapid triage and root cause analysis."

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC7_3Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC7_3Raw {
	raw := CC7_3Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)
	return raw
}
