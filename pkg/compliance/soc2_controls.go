package compliance

import "github.com/varax/operator/pkg/models"

// SOC2Controls returns all SOC2 Trust Services Criteria controls tracked by Varax.
func SOC2Controls() []models.Control {
	return []models.Control{
		{
			ID:          "CC5.1",
			Name:        "Control Activities Over Technology",
			Description: "The entity selects and develops control activities over technology infrastructure to support the achievement of objectives.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC5.2",
			Name:        "Policy and Procedure Controls",
			Description: "The entity deploys control activities through policies that establish what is expected and in procedures that put policies into action.",
			Category:    "Common Criteria",
		},
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
			ID:          "CC6.7",
			Name:        "Data Transmission and Movement Controls",
			Description: "The entity restricts the transmission, movement, and removal of information to authorized internal and external users.",
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
			ID:          "CC7.4",
			Name:        "Respond to Security Incidents",
			Description: "The entity responds to identified security incidents by executing a defined incident response program.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC7.5",
			Name:        "Recover from Security Incidents",
			Description: "The entity identifies, develops, and implements activities to recover from identified security incidents.",
			Category:    "Common Criteria",
		},
		{
			ID:          "CC8.1",
			Name:        "Change Management",
			Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure and software.",
			Category:    "Common Criteria",
		},
		{
			ID:          "A1.1",
			Name:        "Availability Capacity Planning",
			Description: "The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand.",
			Category:    "Availability",
		},
		{
			ID:          "A1.2",
			Name:        "Availability Environmental Protections",
			Description: "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections.",
			Category:    "Availability",
		},
	}
}

// SOC2Mappings returns the mappings from check IDs to SOC2 control IDs.
func SOC2Mappings() []models.ControlMapping {
	return []models.ControlMapping{
		// CC5.1 — Control Activities Over Technology
		{ControlID: "CC5.1", CheckIDs: []string{
			"CIS-1.2.6", "CIS-1.2.7", "CIS-1.2.8", "CIS-1.2.14",
			"CIS-1.3.6", "CIS-4.2.12",
			"PSS-1.1", "PSS-1.2",
		}},
		// CC5.2 — Policy and Procedure Controls
		{ControlID: "CC5.2", CheckIDs: []string{
			"CIS-3.2", "CIS-1.2.16", "CIS-1.2.17",
			"PSS-2.1", "PSS-2.2",
		}},
		// CC6.1 — Logical and Physical Access Controls
		{ControlID: "CC6.1", CheckIDs: []string{
			"CIS-5.1.1", "CIS-5.1.3", "CIS-5.1.8",
			"CIS-1.2.1", "CIS-1.2.2", "CIS-1.2.6", "CIS-1.2.7", "CIS-1.2.8",
			"CIS-1.2.21", "CIS-1.2.25",
			"CIS-2.1", "CIS-2.2",
			"NSA-AA-1", "NSA-AA-2", "NSA-AA-5",
			"RBAC-1", "RBAC-3",
		}},
		// CC6.2 — User Access Provisioning
		{ControlID: "CC6.2", CheckIDs: []string{
			"CIS-5.1.6", "CIS-5.1.5", "CIS-5.1.7",
			"NSA-AA-3", "NSA-AA-4",
		}},
		// CC6.3 — Role-Based Access and Least Privilege
		{ControlID: "CC6.3", CheckIDs: []string{
			"CIS-5.1.1", "CIS-5.1.3", "CIS-5.1.8", "CIS-5.1.4",
			"RBAC-1", "RBAC-2", "RBAC-3", "RBAC-4",
		}},
		// CC6.6 — Security Against Threats Outside System Boundaries
		{ControlID: "CC6.6", CheckIDs: []string{
			"CIS-5.3.2", "CIS-5.3.1", "CIS-5.2.5", "CIS-5.2.6", "CIS-5.2.7", "CIS-5.2.8",
			"NSA-NS-1", "NSA-NS-2", "NSA-NS-3",
		}},
		// CC6.7 — Data Transmission and Movement Controls
		{ControlID: "CC6.7", CheckIDs: []string{
			"CIS-1.2.23", "CIS-1.2.24", "CIS-1.2.26",
			"CIS-2.1", "CIS-2.4",
		}},
		// CC6.8 — Controls Against Malicious Software
		{ControlID: "CC6.8", CheckIDs: []string{
			"CIS-5.2.3", "CIS-5.2.1", "CIS-5.2.2", "CIS-5.2.4", "CIS-5.2.13", "CIS-5.7.2", "CIS-5.7.3",
			"CIS-5.2.9", "CIS-5.2.10", "CIS-5.2.11", "CIS-5.2.12",
			"CIS-4.2.1", "CIS-4.2.2", "CIS-4.2.3", "CIS-4.2.4",
			"NSA-PS-1", "NSA-PS-2", "NSA-PS-3", "NSA-PS-4",
			"NSA-SC-1", "NSA-SC-2",
			"PSS-1.2", "PSS-1.3",
		}},
		// CC7.1 — Detect and Monitor Anomalies
		{ControlID: "CC7.1", CheckIDs: []string{
			"CIS-5.2.3", "CIS-5.3.2", "CIS-5.7.4",
			"CIS-1.2.16", "CIS-1.2.17", "CIS-1.2.18", "CIS-1.2.19",
			"CIS-3.2",
			"NSA-LM-1", "NSA-LM-2",
		}},
		// CC7.2 — Monitor System Components
		{ControlID: "CC7.2", CheckIDs: []string{
			"CIS-5.2.3", "CIS-5.3.2",
			"CIS-4.2.9",
		}},
		// CC7.3 — Evaluate Security Events
		{ControlID: "CC7.3", CheckIDs: []string{
			"CIS-5.2.3", "CIS-5.3.2",
			"CIS-3.2",
		}},
		// CC7.4 — Respond to Security Incidents
		{ControlID: "CC7.4", CheckIDs: []string{
			"CIS-1.2.9", "CIS-1.2.20",
		}},
		// CC7.5 — Recover from Security Incidents
		{ControlID: "CC7.5", CheckIDs: []string{
			"CIS-1.2.18", "CIS-1.2.19",
		}},
		// CC8.1 — Change Management
		{ControlID: "CC8.1", CheckIDs: []string{
			"CIS-5.1.2", "CIS-5.4.1",
			"NSA-VM-1",
			"PSS-1.1", "PSS-1.2",
		}},
		// A1.1 — Availability Capacity Planning
		{ControlID: "A1.1", CheckIDs: []string{
			"CIS-5.7.1",
			"NSA-PS-8",
		}},
		// A1.2 — Availability Environmental Protections
		{ControlID: "A1.2", CheckIDs: []string{
			"CIS-1.3.1",
			"CIS-4.2.5", "CIS-4.2.6", "CIS-4.2.7",
		}},
	}
}
