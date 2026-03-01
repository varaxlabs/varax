package compliance

import "github.com/kubeshield/operator/pkg/models"

// SOC2Controls returns all SOC2 Trust Services Criteria controls tracked by KubeShield.
func SOC2Controls() []models.Control {
	return []models.Control{
		{
			ID:          "CC6.1",
			Name:        "Logical and Physical Access Controls",
			Description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC6.2",
			Name:        "User Access Provisioning",
			Description: "Prior to issuing system credentials, the entity registers and authorizes new internal and external users.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC6.3",
			Name:        "Role-Based Access and Least Privilege",
			Description: "The entity authorizes, modifies, or removes access to data, software, functions, and other protected IT resources based on roles.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC6.6",
			Name:        "Security Against Threats Outside System Boundaries",
			Description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC6.8",
			Name:        "Controls Against Malicious Software",
			Description: "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC7.1",
			Name:        "Detect and Monitor Anomalies",
			Description: "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC7.2",
			Name:        "Monitor System Components for Anomalies",
			Description: "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC7.3",
			Name:        "Evaluate Security Events",
			Description: "The entity evaluates detected security events and determines whether they could or have resulted in a failure of the entity to meet its objectives.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC8.1",
			Name:        "Change Management",
			Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure and software.",
			Category:    "Common Criteria",
		},
	}
}

// SOC2Mappings returns the mappings from CIS check IDs to SOC2 control IDs.
func SOC2Mappings() []models.ControlMapping {
	return []models.ControlMapping{
		{ControlID: "CC6.1", CheckIDs: []string{"CIS-5.1.1", "CIS-5.1.3", "CIS-5.1.8"}},
		{ControlID: "CC6.2", CheckIDs: []string{"CIS-5.1.6", "CIS-5.1.5"}},
		{ControlID: "CC6.3", CheckIDs: []string{"CIS-5.1.1", "CIS-5.1.3", "CIS-5.1.8"}},
		{ControlID: "CC6.6", CheckIDs: []string{"CIS-5.3.2", "CIS-5.2.5", "CIS-5.2.6", "CIS-5.2.7", "CIS-5.2.8"}},
		{ControlID: "CC6.8", CheckIDs: []string{"CIS-5.2.3", "CIS-5.2.1", "CIS-5.2.2", "CIS-5.2.4", "CIS-5.2.13", "CIS-5.7.2", "CIS-5.7.3"}},
		{ControlID: "CC7.1", CheckIDs: []string{"CIS-5.2.3", "CIS-5.3.2", "CIS-5.7.4"}},
		{ControlID: "CC7.2", CheckIDs: []string{"CIS-5.2.3", "CIS-5.3.2"}},
		{ControlID: "CC7.3", CheckIDs: []string{"CIS-5.2.3", "CIS-5.3.2"}},
		{ControlID: "CC8.1", CheckIDs: []string{"CIS-5.1.2", "CIS-5.4.1"}},
	}
}
