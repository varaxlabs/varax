package narrative

import (
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
)

type CC8_1Raw struct {
	SecretsInEnvCount  int
	ImagePinningPass   bool
	SBOMAttested       bool
	ImageSigningPass   bool
	EncryptionAtRest   bool
	Findings           []Finding
	PassCount          int
	FailCount          int
}

type CC8_1Narrative struct {
	ChangeControlSummary string
	SupplyChainSummary   string
	EncryptionSummary    string
	Findings              []Finding
	AssessmentStatement  string
}

func (n CC8_1Narrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	for _, body := range []string{n.ChangeControlSummary, n.SupplyChainSummary, n.EncryptionSummary, n.AssessmentStatement} {
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

func BuildCC8_1(raw CC8_1Raw) CC8_1Narrative {
	var n CC8_1Narrative

	if raw.SecretsInEnvCount == 0 {
		n.ChangeControlSummary = "The organization enforces change management controls through a combination of infrastructure-as-code practices, image provenance verification, and secrets management. Sensitive configuration data is managed through Kubernetes Secrets rather than environment variables, preventing credential exposure in container specifications and process listings."
	} else {
		n.ChangeControlSummary = fmt.Sprintf(
			"The organization enforces change management controls through infrastructure-as-code practices and image provenance verification. However, %s currently %s secrets exposed through environment variables. Environment variable secrets are visible in pod specifications and process listings; migrating to Kubernetes Secrets or an external secrets manager reduces this exposure.",
			pluralize(raw.SecretsInEnvCount, "container", "containers"),
			verbAgreement(raw.SecretsInEnvCount),
		)
	}

	var chainParts []string
	if raw.ImagePinningPass {
		chainParts = append(chainParts, "container images are pinned to immutable digests, preventing unauthorized image substitution")
	}
	if raw.ImageSigningPass {
		chainParts = append(chainParts, "image signatures are verified before deployment, establishing a chain of trust from build to runtime")
	}
	if raw.SBOMAttested {
		chainParts = append(chainParts, "Software Bill of Materials (SBOM) attestations provide supply chain transparency for deployed artifacts")
	}
	if len(chainParts) > 0 {
		n.SupplyChainSummary = "Supply chain integrity controls are in place: " + strings.Join(chainParts, "; ") + "."
	}

	if raw.EncryptionAtRest {
		n.EncryptionSummary = "Encryption at rest is configured for the cluster's persistent data store, protecting Kubernetes Secrets and other sensitive state data from unauthorized access at the storage layer."
	}

	n.Findings = raw.Findings

	status := statusLabel(raw.PassCount, raw.FailCount)
	n.AssessmentStatement = fmt.Sprintf("Assessment: %s — %s.", status, countByStatus(raw.PassCount, raw.FailCount))

	return n
}

func extractCC8_1Raw(cr models.ControlResult, items []evidence.EvidenceItem) CC8_1Raw {
	raw := CC8_1Raw{}
	raw.PassCount, raw.FailCount = countCheckStatus(cr)
	raw.Findings = extractFindings(cr)

	for _, c := range cr.CheckResults {
		switch c.ID {
		case "CIS-5.4.1":
			if c.Status == models.StatusPass {
				raw.SecretsInEnvCount = 0
			} else {
				raw.SecretsInEnvCount = len(c.Evidence)
				if raw.SecretsInEnvCount == 0 {
					raw.SecretsInEnvCount = 1
				}
			}
		case "SC-001":
			raw.SBOMAttested = c.Status == models.StatusPass
		case "SC-002":
			raw.ImageSigningPass = c.Status == models.StatusPass
		case "CIS-5.1.2":
			raw.EncryptionAtRest = c.Status == models.StatusPass
		}
	}

	// Check image pinning from workload hygiene
	for _, c := range cr.CheckResults {
		if c.ID == "NSA-VM-1" || c.ID == "PSS-1.1" {
			if c.Status == models.StatusPass {
				raw.ImagePinningPass = true
			}
		}
	}

	return raw
}
