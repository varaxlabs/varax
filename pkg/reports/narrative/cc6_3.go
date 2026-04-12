package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC6_3Raw struct {
	TotalRoleBindings      int
	NamespaceScopedCount   int
	NamespaceScopedPercent int
	WildcardRoles          []string
	Findings               []Finding
	PassCount              int
	FailCount              int
}

type CC6_3Narrative struct {
	ScopingSummary      string
	WildcardSummary     string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC6_3Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.ScopingSummary, n.WildcardSummary, n.AssessmentStatement} {
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

func BuildCC6_3(raw CC6_3Raw) CC6_3Narrative {
	var n CC6_3Narrative

	// Lead with the least privilege approach
	if raw.TotalRoleBindings > 0 {
		n.ScopingSummary = fmt.Sprintf(
			"The organization enforces role-based access and least privilege through Kubernetes RBAC, which assigns permissions based on operational roles rather than individual identity. Access permissions are scoped to minimize the impact of compromised credentials: %d%% of role bindings (%d of %d) are restricted to specific namespaces rather than granted cluster-wide.",
			raw.NamespaceScopedPercent,
			raw.NamespaceScopedCount,
			raw.TotalRoleBindings,
		)
	} else {
		n.ScopingSummary = "The organization enforces role-based access and least privilege through Kubernetes RBAC, which assigns permissions based on operational roles rather than individual identity."
	}

	if len(raw.WildcardRoles) == 0 {
		n.WildcardSummary = "All ClusterRoles specify explicit resource and verb permissions. No wildcard (*) grants were identified, confirming that access is scoped to the minimum necessary for each role's function."
	} else {
		n.WildcardSummary = fmt.Sprintf(
			"%s %s wildcard (*) resource permissions: %s. Wildcard grants provide broader access than the principle of least privilege requires and should be replaced with explicit resource and verb specifications.",
			pluralize(len(raw.WildcardRoles), "ClusterRole", "ClusterRoles"),
			verbAgreement(len(raw.WildcardRoles)),
			joinList(raw.WildcardRoles),
		)
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC6_3Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC6_3Raw {
	raw := CC6_3Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	if item := findEvidenceByType(items, "rbac-namespace-scope"); item != nil {
		if snap, ok := item.Data.(evidence.NamespaceScopeSnapshot); ok {
			raw.TotalRoleBindings = snap.TotalRoleBindings
			raw.NamespaceScopedCount = snap.NamespaceScopedCount
			raw.NamespaceScopedPercent = snap.NamespaceScopedPercent
		}
	}

	if item := findEvidenceByType(items, "rbac-cluster-admin"); item != nil {
		if snap, ok := item.Data.(evidence.RBACSnapshot); ok {
			raw.WildcardRoles = snap.WildcardRoles
		}
	}

	return raw
}
