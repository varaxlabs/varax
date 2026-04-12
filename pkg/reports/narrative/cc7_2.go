package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC7_2Raw struct {
	Findings  []Finding
	PassCount int
	FailCount int
}

type CC7_2Narrative struct {
	MonitoringSummary   string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC7_2Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.MonitoringSummary, n.AssessmentStatement} {
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

func BuildCC7_2(raw CC7_2Raw) CC7_2Narrative {
	var n CC7_2Narrative

	total := raw.PassCount + raw.FailCount
	if total > 0 {
		n.MonitoringSummary = fmt.Sprintf(
			"The organization monitors system components and their operation for anomalies through automated security scanning and workload health monitoring. A centralized compliance scanning system provides a consolidated view of the cluster's security posture, covering privileged container detection, network policy enforcement, workload health probes, and resource utilization. Automated scans assess %s across these domains, providing ongoing visibility into configuration drift and security baseline deviations.",
			pluralize(total, "control point", "control points"),
		)
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC7_2Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC7_2Raw {
	raw := CC7_2Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)
	return raw
}
