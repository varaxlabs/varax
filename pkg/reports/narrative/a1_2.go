package narrative

import (
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type A1_2Raw struct {
	PDBCoverage        bool
	ReplicaMinimums    bool
	LivenessProbes     bool
	ReadinessProbes    bool
	TerminationGrace   bool
	Findings           []Finding
	PassCount          int
	FailCount          int
}

type A1_2Narrative struct {
	AvailabilitySummary string
	ResilienceDetails   string
	Findings             []Finding
	AssessmentStatement string
}

func (n A1_2Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.AvailabilitySummary, n.ResilienceDetails, n.AssessmentStatement} {
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

func BuildA1_2(raw A1_2Raw) A1_2Narrative {
	var n A1_2Narrative

	var protections []string
	if raw.PDBCoverage {
		protections = append(protections, "PodDisruptionBudgets are configured for multi-replica workloads")
	}
	if raw.ReplicaMinimums {
		protections = append(protections, "critical workloads run multiple replicas")
	}
	if raw.LivenessProbes {
		protections = append(protections, "liveness probes enable self-healing")
	}
	if raw.ReadinessProbes {
		protections = append(protections, "readiness probes manage traffic routing")
	}

	if len(protections) > 0 {
		n.AvailabilitySummary = "The organization implements environmental protections to maintain workload availability and ensure controlled degradation during maintenance and failure scenarios. " + strings.Join(protections, "; ") + "."
	} else {
		n.AvailabilitySummary = "The organization should implement environmental protections to maintain workload availability. PodDisruptionBudgets, multi-replica deployments, and health probes provide defense against both planned maintenance and unexpected failures."
	}

	var missing []string
	if !raw.PDBCoverage {
		missing = append(missing, "PodDisruptionBudgets (controlled disruption during maintenance)")
	}
	if !raw.LivenessProbes {
		missing = append(missing, "liveness probes (self-healing of unhealthy containers)")
	}
	if !raw.ReadinessProbes {
		missing = append(missing, "readiness probes (traffic management during startup and degradation)")
	}
	if len(missing) > 0 {
		n.ResilienceDetails = fmt.Sprintf(
			"Workload resilience gaps identified: %s %s not fully deployed across audited workloads.",
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

func extractA1_2Raw(cr models.ControlResult, items []evidence.EvidenceItem) A1_2Raw {
	raw := A1_2Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	for _, c := range cr.CheckResults {
		switch c.ID {
		case "WH-005":
			raw.PDBCoverage = c.Status == models.StatusPass
		case "WH-004":
			raw.ReplicaMinimums = c.Status == models.StatusPass
		case "WH-003":
			raw.LivenessProbes = c.Status == models.StatusPass
			raw.ReadinessProbes = c.Status == models.StatusPass
		case "CIS-4.2.5":
			raw.TerminationGrace = c.Status == models.StatusPass
		}
	}

	return raw
}
