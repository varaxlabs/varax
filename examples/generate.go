//go:build ignore

// generate.go creates sample HTML reports using synthetic data.
// Run with: go run examples/generate.go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/varax/operator/pkg/compliance"
	"github.com/varax/operator/pkg/evidence"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/reports"
)

func main() {
	gen := reports.NewGenerator("1.0.0")

	scanResults := buildScanResults()
	complianceResult := buildComplianceResult(scanResults)
	evidenceBundle := buildEvidence()

	data := &reports.ReportData{
		GeneratedAt:      time.Date(2026, 3, 7, 14, 30, 0, 0, time.UTC),
		ClusterName:      "prod-eks-us-east-1",
		Compliance:       complianceResult,
		Scan:             scanResults,
		Evidence:         evidenceBundle,
		HistoricalScores: []float64{62, 68, 72, 75, 78},
	}

	// Generate readiness report
	fmt.Println("Generating readiness report...")
	if err := gen.Generate(reports.ReportRequest{
		Type:       reports.ReportTypeReadiness,
		Format:     reports.FormatHTML,
		OutputPath: "examples/readiness-report.html",
	}, data); err != nil {
		fmt.Fprintf(os.Stderr, "readiness report: %v\n", err)
		os.Exit(1)
	}

	// Generate executive report
	fmt.Println("Generating executive report...")
	if err := gen.Generate(reports.ReportRequest{
		Type:       reports.ReportTypeExecutive,
		Format:     reports.FormatHTML,
		OutputPath: "examples/executive-report.html",
	}, data); err != nil {
		fmt.Fprintf(os.Stderr, "executive report: %v\n", err)
		os.Exit(1)
	}

	// Generate CC6.1 control detail page
	fmt.Println("Generating CC6.1 evidence detail...")
	var cc61Control models.ControlResult
	for _, cr := range complianceResult.ControlResults {
		if cr.Control.ID == "CC6.1" {
			cc61Control = cr
			break
		}
	}
	cc61Evidence := reports.FilterEvidenceForControl(evidenceBundle, "CC6.1")
	if err := gen.GenerateControlDetail(
		"examples/evidence-CC6.1.html",
		reports.FormatHTML,
		cc61Control,
		cc61Evidence,
	); err != nil {
		fmt.Fprintf(os.Stderr, "evidence detail: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Done. Generated:")
	fmt.Println("  examples/readiness-report.html")
	fmt.Println("  examples/executive-report.html")
	fmt.Println("  examples/evidence-CC6.1.html")
}

func buildScanResults() *models.ScanResult {
	results := []models.CheckResult{
		// --- Customer-controlled checks (CIS 5.x) ---
		// RBAC checks — mixed results
		check("CIS-5.1.1", "Restrict cluster-admin ClusterRoleBinding usage", "CIS", "5.1", models.SeverityCritical, models.StatusPass,
			"Only 2 cluster-admin bindings found (system defaults)"),
		check("CIS-5.1.2", "Minimize access to secrets", "CIS", "5.1", models.SeverityHigh, models.StatusFail,
			"3 roles grant get/list/watch on secrets: dev-team, monitoring, ci-deploy"),
		check("CIS-5.1.3", "Minimize wildcard use in Roles and ClusterRoles", "CIS", "5.1", models.SeverityHigh, models.StatusFail,
			"2 ClusterRoles use wildcard resources: legacy-admin, dev-full-access"),
		check("CIS-5.1.4", "Minimize access to create pods", "CIS", "5.1", models.SeverityMedium, models.StatusPass,
			"Pod creation restricted to appropriate roles"),
		check("CIS-5.1.5", "Ensure default service accounts are not actively used", "CIS", "5.1", models.SeverityMedium, models.StatusWarn,
			"2 namespaces use default service account: staging, dev"),
		check("CIS-5.1.6", "Ensure service account tokens are not auto-mounted", "CIS", "5.1", models.SeverityMedium, models.StatusPass,
			"All service accounts have automountServiceAccountToken: false"),
		check("CIS-5.1.7", "Avoid use of system:masters group", "CIS", "5.1", models.SeverityHigh, models.StatusPass,
			"No bindings to system:masters group found"),
		check("CIS-5.1.8", "Limit use of bind, escalate, and impersonate permissions", "CIS", "5.1", models.SeverityHigh, models.StatusPass,
			"No roles grant bind/escalate/impersonate"),

		// Pod security checks — some failures
		check("CIS-5.2.1", "Ensure allowPrivilegeEscalation is set to false", "CIS", "5.2", models.SeverityCritical, models.StatusFail,
			"4 containers allow privilege escalation in namespace: production"),
		check("CIS-5.2.2", "Ensure containers run as non-root", "CIS", "5.2", models.SeverityHigh, models.StatusPass,
			"All containers specify runAsNonRoot: true"),
		check("CIS-5.2.3", "Minimize privileged containers", "CIS", "5.2", models.SeverityCritical, models.StatusFail,
			"1 privileged container: monitoring/node-exporter"),
		check("CIS-5.2.4", "Ensure containers drop ALL capabilities", "CIS", "5.2", models.SeverityHigh, models.StatusWarn,
			"6 containers do not drop all capabilities"),
		check("CIS-5.2.5", "Ensure hostPID is not set", "CIS", "5.2", models.SeverityCritical, models.StatusPass,
			"No pods use hostPID"),
		check("CIS-5.2.6", "Ensure hostIPC is not set", "CIS", "5.2", models.SeverityHigh, models.StatusPass,
			"No pods use hostIPC"),
		check("CIS-5.2.7", "Ensure hostNetwork is not set", "CIS", "5.2", models.SeverityHigh, models.StatusPass,
			"No pods use hostNetwork"),
		check("CIS-5.2.8", "Limit container hostPort usage", "CIS", "5.2", models.SeverityMedium, models.StatusPass,
			"No containers use hostPort"),
		check("CIS-5.2.13", "Minimize added capabilities", "CIS", "5.2", models.SeverityMedium, models.StatusPass,
			"No unnecessary capabilities added"),

		// Network policies
		check("CIS-5.3.1", "Ensure CNI supports NetworkPolicy", "CIS", "5.3", models.SeverityHigh, models.StatusPass,
			"CNI supports NetworkPolicy (Calico detected)"),
		check("CIS-5.3.2", "Ensure every namespace has a NetworkPolicy", "CIS", "5.3", models.SeverityHigh, models.StatusFail,
			"3 namespaces missing NetworkPolicy: staging, dev, monitoring"),

		// Secrets management
		check("CIS-5.4.1", "Prefer using Secrets as files over environment variables", "CIS", "5.4", models.SeverityMedium, models.StatusFail,
			"8 pods reference secrets via environment variables"),

		// General security
		check("CIS-5.7.1", "Create resource quota for namespaces", "CIS", "5.7", models.SeverityMedium, models.StatusWarn,
			"2 namespaces without resource quotas: dev, staging"),
		check("CIS-5.7.2", "Ensure Seccomp profile is set", "CIS", "5.7", models.SeverityMedium, models.StatusPass,
			"RuntimeDefault seccomp profile applied"),
		check("CIS-5.7.3", "Ensure security context is applied to pods and containers", "CIS", "5.7", models.SeverityHigh, models.StatusPass,
			"All pods have security context set"),
		check("CIS-5.7.4", "Ensure default namespace is not used", "CIS", "5.7", models.SeverityMedium, models.StatusPass,
			"No workloads in default namespace"),

		// --- Provider-managed checks (CIS 1.x, 2.x, 3.x) ---
		providerManaged("CIS-1.2.1", "Ensure anonymous auth is disabled", "CIS", "1.2", models.SeverityCritical),
		providerManaged("CIS-1.2.2", "Ensure token auth file is not set", "CIS", "1.2", models.SeverityCritical),
		providerManaged("CIS-1.2.6", "Ensure authorization mode includes RBAC", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.7", "Ensure authorization mode excludes AlwaysAllow", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.8", "Ensure authorization mode includes Node", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-2.1", "Ensure etcd encryption is configured", "CIS", "2.x", models.SeverityHigh),
		providerManaged("CIS-2.2", "Ensure etcd peer TLS is enabled", "CIS", "2.x", models.SeverityHigh),
		providerManaged("CIS-3.2", "Ensure audit policy covers key operations", "CIS", "3.x", models.SeverityHigh),

		// --- NSA/CISA checks ---
		check("NSA-NS-1", "Ensure namespaces are used to isolate workloads", "NSA", "Network Security", models.SeverityHigh, models.StatusPass,
			"Workloads properly isolated across namespaces"),
		check("NSA-PS-1", "Ensure Pod Security Standards are enforced", "NSA", "Pod Security", models.SeverityHigh, models.StatusPass,
			"Pod Security Admission enforced at namespace level"),
		check("NSA-AA-1", "Ensure strong authentication is configured", "NSA", "Authentication", models.SeverityHigh, models.StatusPass,
			"OIDC authentication configured"),

		// --- PSS checks ---
		check("PSS-1.1", "Enforce Baseline Pod Security Standard", "PSS", "Pod Security", models.SeverityHigh, models.StatusPass,
			"Baseline PSS enforced on all non-system namespaces"),
		check("PSS-1.2", "Enforce Restricted Pod Security Standard", "PSS", "Pod Security", models.SeverityHigh, models.StatusWarn,
			"Restricted PSS enforced on 4 of 6 production namespaces"),

		// --- RBAC checks ---
		check("RBAC-1", "Audit cluster-admin usage", "RBAC", "Access Control", models.SeverityHigh, models.StatusPass,
			"cluster-admin limited to break-glass accounts"),
		check("RBAC-2", "Verify least-privilege role bindings", "RBAC", "Access Control", models.SeverityHigh, models.StatusFail,
			"3 overly permissive role bindings found"),
	}

	// Compute summary
	summary := models.ScanSummary{TotalChecks: len(results)}
	for _, r := range results {
		switch r.Status {
		case models.StatusPass:
			summary.PassCount++
		case models.StatusFail:
			summary.FailCount++
		case models.StatusWarn:
			summary.WarnCount++
		case models.StatusSkip:
			summary.SkipCount++
		case models.StatusProviderManaged:
			summary.ProviderManagedCount++
		}
	}

	return &models.ScanResult{
		ID:        "sample-scan-001",
		Timestamp: time.Date(2026, 3, 7, 14, 28, 0, 0, time.UTC),
		Duration:  4*time.Second + 230*time.Millisecond,
		Results:   results,
		Summary:   summary,
	}
}

func check(id, name, benchmark, section string, severity models.Severity, status models.CheckStatus, msg string) models.CheckResult {
	return models.CheckResult{
		ID:        id,
		Name:      name,
		Benchmark: benchmark,
		Section:   section,
		Severity:  severity,
		Status:    status,
		Message:   msg,
	}
}

func providerManaged(id, name, benchmark, section string, severity models.Severity) models.CheckResult {
	return models.CheckResult{
		ID:        id,
		Name:      name,
		Benchmark: benchmark,
		Section:   section,
		Severity:  severity,
		Status:    models.StatusProviderManaged,
		Message:   "Control plane managed by AWS EKS. See AWS shared responsibility model.",
	}
}

func buildComplianceResult(scan *models.ScanResult) *models.ComplianceResult {
	controls := compliance.SOC2Controls()
	mappings := compliance.SOC2Mappings()

	// Build check result lookup
	checkMap := make(map[string]models.CheckResult, len(scan.Results))
	for _, r := range scan.Results {
		checkMap[r.ID] = r
	}

	// Build mapping lookup
	controlChecks := make(map[string][]string, len(mappings))
	for _, m := range mappings {
		controlChecks[m.ControlID] = m.CheckIDs
	}

	var controlResults []models.ControlResult
	for _, ctrl := range controls {
		checkIDs := controlChecks[ctrl.ID]
		var matched []models.CheckResult
		for _, cid := range checkIDs {
			if cr, ok := checkMap[cid]; ok {
				matched = append(matched, cr)
			}
		}

		status, violations := evaluateControl(matched)
		controlResults = append(controlResults, models.ControlResult{
			Control:        ctrl,
			Status:         status,
			ViolationCount: violations,
			CheckResults:   matched,
		})
	}

	// Calculate score
	var assessed, passing float64
	for _, cr := range controlResults {
		if cr.Status == models.ControlStatusNotAssessed {
			continue
		}
		assessed++
		if cr.Status == models.ControlStatusPass {
			passing++
		} else if cr.Status == models.ControlStatusPartial {
			passing += 0.5
		}
	}

	score := 0.0
	if assessed > 0 {
		score = (passing / assessed) * 100
	}

	return &models.ComplianceResult{
		Framework:      "SOC2",
		Score:          score,
		ControlResults: controlResults,
	}
}

func evaluateControl(checks []models.CheckResult) (models.ControlStatus, int) {
	if len(checks) == 0 {
		return models.ControlStatusNotAssessed, 0
	}

	var pass, fail, violations int
	for _, c := range checks {
		switch c.Status {
		case models.StatusPass, models.StatusProviderManaged:
			pass++
		case models.StatusFail:
			fail++
			violations++
		}
	}

	switch {
	case fail == 0:
		return models.ControlStatusPass, 0
	case pass == 0:
		return models.ControlStatusFail, violations
	default:
		return models.ControlStatusPartial, violations
	}
}

func buildEvidence() *evidence.EvidenceBundle {
	ts := time.Date(2026, 3, 7, 14, 28, 0, 0, time.UTC)
	return &evidence.EvidenceBundle{
		CollectedAt: ts,
		ClusterName: "prod-eks-us-east-1",
		Items: []evidence.EvidenceItem{
			{
				Category:    "RBAC",
				Description: "ClusterRoleBinding snapshot - cluster-admin bindings",
				Timestamp:   ts,
				Data: map[string]any{
					"bindings": []map[string]any{
						{
							"name":    "system:masters",
							"role":    "cluster-admin",
							"subject": "system:masters group",
							"type":    "Group",
						},
						{
							"name":    "eks-admin-binding",
							"role":    "cluster-admin",
							"subject": "break-glass-admin",
							"type":    "User",
						},
					},
					"totalBindings": 2,
					"assessment":    "Only system defaults and break-glass accounts have cluster-admin access",
				},
			},
			{
				Category:    "RBAC",
				Description: "Service account token auto-mount audit",
				Timestamp:   ts,
				Data: map[string]any{
					"namespacesAudited":           12,
					"serviceAccountsWithAutoMount": 0,
					"compliant":                    true,
				},
			},
			{
				Category:    "Network",
				Description: "NetworkPolicy coverage by namespace",
				Timestamp:   ts,
				Data: map[string]any{
					"totalNamespaces":    12,
					"coveredNamespaces":  9,
					"missingNamespaces":  []string{"staging", "dev", "monitoring"},
					"coveragePercentage": 75,
				},
			},
			{
				Category:    "Audit",
				Description: "EKS control plane audit logging configuration",
				Timestamp:   ts,
				Data: map[string]any{
					"clusterName":    "prod-eks-us-east-1",
					"provider":       "EKS",
					"loggingEnabled": true,
					"logTypes":       []string{"api", "audit", "authenticator", "controllerManager", "scheduler"},
					"retentionDays":  90,
				},
			},
			{
				Category:    "Encryption",
				Description: "Secrets encryption configuration",
				Timestamp:   ts,
				Data: map[string]any{
					"provider":         "aws-encryption-provider",
					"kmsKeyArn":        "arn:aws:kms:us-east-1:123456789012:key/sample-key-id",
					"encryptedAtRest":  true,
					"rotationEnabled":  true,
				},
			},
		},
	}
}
