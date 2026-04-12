package narrative

import (
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type A1_1Raw struct {
	ResourceQuotasPass bool
	LimitRangesPass    bool
	ResourceLimitsPass bool
	Findings           []Finding
	PassCount          int
	FailCount          int
}

type A1_1Narrative struct {
	CapacitySummary     string
	GovernanceDetails   string
	Findings             []Finding
	AssessmentStatement string
}

func (n A1_1Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.CapacitySummary, n.GovernanceDetails, n.AssessmentStatement} {
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

func BuildA1_1(raw A1_1Raw) A1_1Narrative {
	var n A1_1Narrative

	var controls []string
	if raw.ResourceQuotasPass {
		controls = append(controls, "ResourceQuotas enforce per-namespace CPU, memory, and pod count limits")
	}
	if raw.LimitRangesPass {
		controls = append(controls, "LimitRanges set default container resource constraints")
	}
	if raw.ResourceLimitsPass {
		controls = append(controls, "all containers have CPU and memory limits defined")
	}

	if len(controls) > 0 {
		n.CapacitySummary = "The organization maintains and monitors processing capacity through Kubernetes resource management controls that prevent resource exhaustion and ensure fair scheduling across workloads. " + strings.Join(controls, ". ") + "."
	} else {
		n.CapacitySummary = "The organization should implement Kubernetes resource management controls to maintain and monitor processing capacity. Resource quotas, limit ranges, and per-container resource limits prevent resource exhaustion and ensure fair scheduling across workloads."
	}

	var missing []string
	if !raw.ResourceQuotasPass {
		missing = append(missing, "ResourceQuotas (namespace-level aggregate limits)")
	}
	if !raw.LimitRangesPass {
		missing = append(missing, "LimitRanges (default container constraints)")
	}
	if !raw.ResourceLimitsPass {
		missing = append(missing, "per-container resource limits")
	}
	if len(missing) > 0 {
		n.GovernanceDetails = fmt.Sprintf(
			"Capacity management gaps identified: %s %s not fully configured across all namespaces.",
			joinList(missing),
			func() string {
				if len(missing) == 1 {
					return "is"
				}
				return "are"
			}(),
		)
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractA1_1Raw(cr models.ControlResult, items []evidence.EvidenceItem) A1_1Raw {
	raw := A1_1Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	for _, c := range cr.CheckResults {
		switch c.ID {
		case "NG-001":
			raw.ResourceQuotasPass = c.Status == models.StatusPass
		case "CIS-5.7.1":
			raw.ResourceLimitsPass = c.Status == models.StatusPass
		case "NSA-PS-8":
			if c.Status == models.StatusPass {
				raw.ResourceLimitsPass = true
			}
		}
	}

	return raw
}
