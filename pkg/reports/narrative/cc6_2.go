package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC6_2Raw struct {
	ServiceAccountCount int
	AutoMountCount      int
	NamespacesAudited   int
	Findings            []Finding
	PassCount           int
	FailCount           int
}

type CC6_2Narrative struct {
	ProvisioningSummary string
	TokenSummary        string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC6_2Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.ProvisioningSummary, n.TokenSummary, n.AssessmentStatement} {
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

func BuildCC6_2(raw CC6_2Raw) CC6_2Narrative {
	var n CC6_2Narrative

	// Lead with how the organization manages user provisioning
	provBase := "The organization manages system credential provisioning through Kubernetes service accounts and role-based access bindings. Prior to granting access, users and automated workloads are assigned dedicated service accounts with permissions scoped to their operational requirements."
	if raw.ServiceAccountCount > 0 {
		n.ProvisioningSummary = fmt.Sprintf(
			"%s The cluster maintains %s across %s, each bound to specific roles that define permitted operations.",
			provBase,
			pluralize(raw.ServiceAccountCount, "service account", "service accounts"),
			pluralize(raw.NamespacesAudited, "namespace", "namespaces"),
		)
	} else {
		n.ProvisioningSummary = provBase
	}

	if raw.AutoMountCount == 0 && raw.NamespacesAudited > 0 {
		n.TokenSummary = "Credential exposure is controlled by disabling automatic service account token mounting across all audited namespaces. Workloads that require Kubernetes API access must explicitly opt in to credential mounting, reducing the attack surface for credential theft."
	} else if raw.AutoMountCount > 0 {
		n.TokenSummary = fmt.Sprintf(
			"%s %s automatic credential mounting enabled. These service accounts should be reviewed to confirm the associated workloads require direct Kubernetes API access.",
			pluralize(raw.AutoMountCount, "service account", "service accounts"),
			verbAgreement(raw.AutoMountCount),
		)
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC6_2Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC6_2Raw {
	raw := CC6_2Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	if item := findEvidenceByType(items, "rbac-cluster-admin"); item != nil {
		if snap, ok := item.Data.(evidence.RBACSnapshot); ok {
			raw.ServiceAccountCount = snap.ServiceAccountCount
		}
	}
	if item := findEvidenceByType(items, "rbac-sa-token-mount"); item != nil {
		if snap, ok := item.Data.(evidence.SATokenMountSnapshot); ok {
			raw.AutoMountCount = snap.AutoMountCount
			raw.NamespacesAudited = snap.NamespacesAudited
		}
	}

	return raw
}
