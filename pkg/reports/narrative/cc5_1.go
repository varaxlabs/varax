package narrative

import (
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC5_1Raw struct {
	PSSEnforceCount  int
	PSSWarnCount     int
	PSSAuditCount    int
	TotalNamespaces  int
	Findings         []Finding
	PassCount        int
	FailCount        int
}

type CC5_1Narrative struct {
	TechControlSummary  string
	PSSDetails          string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC5_1Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.TechControlSummary, n.PSSDetails, n.AssessmentStatement} {
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

func BuildCC5_1(raw CC5_1Raw) CC5_1Narrative {
	var n CC5_1Narrative

	n.TechControlSummary = "The organization selects and develops technology control activities through Kubernetes Pod Security Standards (PSS) and admission controllers. PSS provides three graduated security profiles — Privileged, Baseline, and Restricted — that enforce container security boundaries at the namespace level. Admission controllers serve as automated policy enforcement gates, validating workload configurations against these standards before deployment and preventing non-compliant resources from being created in the cluster."

	var pssDetails []string
	if raw.PSSEnforceCount > 0 {
		pssDetails = append(pssDetails, fmt.Sprintf("%s in enforce mode (non-compliant workloads are rejected)", pluralize(raw.PSSEnforceCount, "namespace", "namespaces")))
	}
	if raw.PSSWarnCount > 0 {
		pssDetails = append(pssDetails, fmt.Sprintf("%s in warn mode", pluralize(raw.PSSWarnCount, "namespace", "namespaces")))
	}
	if raw.PSSAuditCount > 0 {
		pssDetails = append(pssDetails, fmt.Sprintf("%s in audit mode", pluralize(raw.PSSAuditCount, "namespace", "namespaces")))
	}
	if len(pssDetails) > 0 {
		n.PSSDetails = "Current Pod Security Standards enforcement: " + strings.Join(pssDetails, ", ") + "."
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC5_1Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC5_1Raw {
	raw := CC5_1Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)
	return raw
}
