package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC7_5Raw struct {
	Findings  []Finding
	PassCount int
	FailCount int
}

type CC7_5Narrative struct {
	RecoverySummary     string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC7_5Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.RecoverySummary, n.AssessmentStatement} {
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

func BuildCC7_5(raw CC7_5Raw) CC7_5Narrative {
	var n CC7_5Narrative

	n.RecoverySummary = "The organization implements recovery controls to restore normal operations after security incidents. Kubernetes provides declarative state management through its reconciliation loop, which continuously drives the cluster toward the desired state defined in resource specifications. This self-healing capability automatically restarts failed containers, reschedules workloads from unhealthy nodes, and restores configuration state from the cluster's persistent data store. Audit log retention policies ensure that forensic records are preserved to support post-incident analysis and process improvement."

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC7_5Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC7_5Raw {
	raw := CC7_5Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)
	return raw
}
