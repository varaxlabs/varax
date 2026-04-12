package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC6_6Raw struct {
	TotalPolicies          int
	NamespacesWithPolicies int
	TotalNamespaces        int
	NamespacesWithDeny     int
	NamespacesWithoutDeny  []string
	CoveragePercent        int
	Findings               []Finding
	PassCount              int
	FailCount              int
}

type CC6_6Narrative struct {
	CoverageSummary     string
	DefaultDenySummary  string
	GapSummary          string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC6_6Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.CoverageSummary, n.DefaultDenySummary, n.GapSummary, n.AssessmentStatement} {
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

func BuildCC6_6(raw CC6_6Raw) CC6_6Narrative {
	var n CC6_6Narrative

	if raw.TotalNamespaces > 0 {
		n.CoverageSummary = fmt.Sprintf(
			"The organization implements network segmentation controls through Kubernetes NetworkPolicies to restrict lateral movement between workloads and protect against threats from sources outside system boundaries. The cluster enforces %s across %s, providing ingress and egress traffic controls that limit network communication to explicitly authorized paths.",
			pluralize(raw.TotalPolicies, "NetworkPolicy", "NetworkPolicies"),
			pluralize(raw.TotalNamespaces, "namespace", "namespaces"),
		)
	}

	if raw.TotalNamespaces > 0 {
		if raw.NamespacesWithDeny == raw.TotalNamespaces {
			n.DefaultDenySummary = fmt.Sprintf(
				"Default-deny NetworkPolicies are deployed across all %d %s, establishing a zero-trust network posture where all traffic is blocked unless explicitly permitted by policy rules.",
				raw.TotalNamespaces,
				func() string {
					if raw.TotalNamespaces == 1 {
						return "namespace"
					}
					return "namespaces"
				}(),
			)
		} else if raw.NamespacesWithDeny > 0 {
			n.DefaultDenySummary = fmt.Sprintf(
				"Default-deny policies establish a zero-trust baseline in %s of %d, ensuring that only explicitly authorized network connections are permitted in those namespaces.",
				pluralize(raw.NamespacesWithDeny, "namespace", "namespaces"),
				raw.TotalNamespaces,
			)
		} else {
			n.DefaultDenySummary = "No namespaces currently enforce default-deny NetworkPolicies. Without a default-deny baseline, all pod-to-pod communication is permitted unless explicitly restricted, increasing the risk of lateral movement."
		}
	}

	if len(raw.NamespacesWithoutDeny) > 0 && len(raw.NamespacesWithoutDeny) <= 10 {
		n.GapSummary = fmt.Sprintf(
			"Namespaces without default-deny policies: %s.",
			joinList(raw.NamespacesWithoutDeny),
		)
	} else if len(raw.NamespacesWithoutDeny) > 10 {
		n.GapSummary = fmt.Sprintf(
			"%d namespaces lack default-deny policies.",
			len(raw.NamespacesWithoutDeny),
		)
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC6_6Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC6_6Raw {
	raw := CC6_6Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	if item := findEvidenceByType(items, "network-policy-coverage"); item != nil {
		if snap, ok := item.Data.(evidence.NetworkSnapshot); ok {
			raw.TotalPolicies = snap.TotalPolicies
			raw.NamespacesWithPolicies = len(snap.NamespaceSummaries)
		}
	}

	if item := findEvidenceByType(items, "default-deny-status"); item != nil {
		if snap, ok := item.Data.(evidence.DefaultDenySnapshot); ok {
			raw.TotalNamespaces = snap.TotalNamespaces
			raw.NamespacesWithDeny = snap.NamespacesWithDeny
			raw.NamespacesWithoutDeny = snap.NamespacesWithoutDeny
			if snap.TotalNamespaces > 0 {
				raw.CoveragePercent = percent(raw.NamespacesWithPolicies, snap.TotalNamespaces)
			}
		}
	}

	return raw
}
