package narrative

import (
	"fmt"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

// CC6_1Raw contains the raw data needed to build the CC6.1 narrative.
type CC6_1Raw struct {
	TotalClusterRoles      int
	TotalCRBs              int
	TotalRoleBindings      int
	NamespaceScopedCount   int
	NamespaceScopedPercent int
	ClusterAdminCount      int
	ClusterAdminBindings   []BindingDetail
	NamespacesAudited      int
	AutoMountCount         int
	AffectedNamespaceCount int
	OIDCConfigured         bool
	Findings               []Finding
	PassCount              int
	FailCount              int
}

// CC6_1Narrative contains the pre-built narrative paragraphs for CC6.1.
type CC6_1Narrative struct {
	AccessControlSummary string
	ScopingSummary       string
	TokenMountSummary    string
	AuthSummary          string
	Findings             []Finding
	AssessmentStatement  string
}

// Sections implements ControlNarrative.
func (n CC6_1Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{
		n.AccessControlSummary,
		n.ScopingSummary,
		n.TokenMountSummary,
		n.AuthSummary,
	} {
		if body != "" {
			sections = append(sections, NarrativeSection{Body: body})
		}
	}
	if s := findingsSection(n.Findings); len(s.Items) > 0 {
		sections = append(sections, s)
	}
	if n.AssessmentStatement != "" {
		sections = append(sections, NarrativeSection{Body: n.AssessmentStatement})
	}
	return sections
}

// BuildCC6_1 constructs the narrative for CC6.1 — Logical and Physical Access Controls.
func BuildCC6_1(raw CC6_1Raw) CC6_1Narrative {
	var n CC6_1Narrative

	// Paragraph 1: RBAC access control description (organizational voice)
	if raw.TotalClusterRoles > 0 || raw.TotalCRBs > 0 {
		bindingDesc := "No cluster-admin bindings were identified"
		if raw.ClusterAdminCount > 0 {
			subjects := make([]string, len(raw.ClusterAdminBindings))
			for i, b := range raw.ClusterAdminBindings {
				subjects[i] = fmt.Sprintf("%s (%s)", b.Subject, b.Type)
			}
			bindingDesc = fmt.Sprintf("Access to the cluster-admin role, which grants unrestricted administrative privileges, is restricted to %s: %s",
				pluralize(raw.ClusterAdminCount, "authorized binding", "authorized bindings"),
				joinList(subjects))
		}
		n.AccessControlSummary = fmt.Sprintf(
			"The organization enforces logical access controls through Kubernetes Role-Based Access Control (RBAC), which provides granular permission management across all cluster resources. The RBAC configuration comprises %s and %s. %s.",
			pluralize(raw.TotalClusterRoles, "ClusterRole", "ClusterRoles"),
			pluralize(raw.TotalCRBs, "ClusterRoleBinding", "ClusterRoleBindings"),
			bindingDesc,
		)
	}

	// Paragraph 2: Namespace scoping — demonstrates least privilege architecture
	if raw.TotalRoleBindings > 0 {
		n.ScopingSummary = fmt.Sprintf(
			"Access permissions are scoped to minimize blast radius. %d%% of role bindings (%d of %d) are namespace-scoped rather than cluster-wide, enforcing the principle of least privilege through namespace isolation.",
			raw.NamespaceScopedPercent,
			raw.NamespaceScopedCount,
			raw.TotalRoleBindings,
		)
	}

	// Paragraph 3: Service account credential management
	if raw.NamespacesAudited > 0 {
		if raw.AutoMountCount == 0 {
			n.TokenMountSummary = fmt.Sprintf(
				"Service account credential exposure is controlled across all %d audited %s. Automatic mounting of service account tokens is disabled, preventing unintended credential availability to workloads that do not require Kubernetes API access.",
				raw.NamespacesAudited,
				func() string {
					if raw.NamespacesAudited == 1 {
						return "namespace"
					}
					return "namespaces"
				}(),
			)
		} else {
			n.TokenMountSummary = fmt.Sprintf(
				"%s %s automatic service account token mounting enabled. These credentials are automatically available to all containers in the pod and should be reviewed to confirm the workload requires Kubernetes API access.",
				pluralize(raw.AutoMountCount, "service account", "service accounts"),
				verbAgreement(raw.AutoMountCount),
			)
		}
	}

	// Paragraph 4: Authentication method
	if raw.OIDCConfigured {
		n.AuthSummary = "The organization manages authentication through OIDC integration with a centralized identity provider. This provides single sign-on capabilities, centralized user lifecycle management, and integration with the organization's existing identity governance processes."
	}

	// Findings
	n.Findings = raw.Findings

	// Assessment
	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf(
		"Assessment: %s — %s.",
		status,
		countByStatus(raw.PassCount, raw.FailCount),
	)

	return n
}

func extractCC6_1Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC6_1Raw {
	raw := CC6_1Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	// Extract from RBAC snapshot
	if item := findEvidenceByType(items, "rbac-cluster-admin"); item != nil {
		if snap, ok := item.Data.(evidence.RBACSnapshot); ok {
			raw.TotalClusterRoles = snap.ClusterRoleCount
			raw.TotalCRBs = snap.ClusterRoleBindingCount
			raw.ClusterAdminCount = len(snap.ClusterAdminBindings)
			for _, ab := range snap.ClusterAdminBindings {
				raw.ClusterAdminBindings = append(raw.ClusterAdminBindings, BindingDetail{
					Name:    ab.Name,
					Subject: ab.Subject,
					Type:    ab.Type,
				})
			}
		}
	}

	// Extract SA token mount data
	if item := findEvidenceByType(items, "rbac-sa-token-mount"); item != nil {
		if snap, ok := item.Data.(evidence.SATokenMountSnapshot); ok {
			raw.NamespacesAudited = snap.NamespacesAudited
			raw.AutoMountCount = snap.AutoMountCount
		}
	}

	// Extract namespace scope data
	if item := findEvidenceByType(items, "rbac-namespace-scope"); item != nil {
		if snap, ok := item.Data.(evidence.NamespaceScopeSnapshot); ok {
			raw.TotalRoleBindings = snap.TotalRoleBindings
			raw.NamespaceScopedCount = snap.NamespaceScopedCount
			raw.NamespaceScopedPercent = snap.NamespaceScopedPercent
		}
	}

	return raw
}
