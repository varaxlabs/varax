package narrative

import (
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC6_8Raw struct {
	PrivilegedCount    int
	NonRootCount       int
	TotalWorkloads     int
	ReadOnlyRootCount  int
	CapDropAllCount    int
	SeccompCount       int
	Findings           []Finding
	PassCount          int
	FailCount          int
}

type CC6_8Narrative struct {
	SecurityPosture     string
	HardeningDetails    string
	Findings             []Finding
	AssessmentStatement string
}

func (n CC6_8Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.SecurityPosture, n.HardeningDetails, n.AssessmentStatement} {
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

func BuildCC6_8(raw CC6_8Raw) CC6_8Narrative {
	var n CC6_8Narrative

	if raw.PrivilegedCount == 0 {
		n.SecurityPosture = "The organization implements controls to prevent the introduction of unauthorized or malicious software through a defense-in-depth strategy. Kubernetes Pod Security Standards restrict container privileges at the namespace level, and no containers in audited namespaces run in privileged mode. This prevents containers from accessing host resources, kernel capabilities, or device files that could be used to compromise the node or other workloads."
	} else {
		n.SecurityPosture = fmt.Sprintf(
			"The organization implements controls to prevent the introduction of unauthorized or malicious software through Kubernetes Pod Security Standards and container security contexts. However, %s currently %s in privileged mode, which grants full access to the host's resources and should be evaluated for necessity.",
			pluralize(raw.PrivilegedCount, "container", "containers"),
			verbAgreement(raw.PrivilegedCount),
		)
	}

	var details []string
	if raw.NonRootCount > 0 {
		details = append(details, "containers run as non-root users")
	}
	if raw.ReadOnlyRootCount > 0 {
		details = append(details, "read-only root filesystems prevent runtime modification")
	}
	if raw.CapDropAllCount > 0 {
		details = append(details, "Linux capabilities are dropped to the minimum required set")
	}
	if raw.SeccompCount > 0 {
		details = append(details, "Seccomp profiles restrict available system calls")
	}
	if len(details) > 0 {
		n.HardeningDetails = "Additional container hardening measures include: " + strings.Join(details, "; ") + "."
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC6_8Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC6_8Raw {
	raw := CC6_8Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	// Derive container security stats from check results
	for _, c := range cr.CheckResults {
		switch c.ID {
		case "CIS-5.2.3":
			if c.Status == models.StatusPass {
				raw.PrivilegedCount = 0
			} else {
				raw.PrivilegedCount = len(c.Evidence)
			}
			raw.TotalWorkloads++ // Use as a proxy for workload count tracking
		case "CIS-5.2.2":
			if c.Status == models.StatusPass {
				raw.NonRootCount++
			}
		case "CIS-5.2.4":
			if c.Status == models.StatusPass {
				raw.ReadOnlyRootCount++
			}
		case "CIS-5.2.9":
			if c.Status == models.StatusPass {
				raw.CapDropAllCount++
			}
		case "CIS-5.2.13":
			if c.Status == models.StatusPass {
				raw.SeccompCount++
			}
		}
	}

	return raw
}
