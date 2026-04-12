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

	// Historical data — 5 scans over 30 days
	historicalTimes := []time.Time{
		time.Date(2026, 2, 5, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 19, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 26, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 7, 14, 28, 0, 0, time.UTC),
	}

	data := &reports.ReportData{
		GeneratedAt:      time.Date(2026, 3, 7, 14, 30, 0, 0, time.UTC),
		ClusterName:      "prod-eks-us-east-1",
		Compliance:       complianceResult,
		Scan:             scanResults,
		Evidence:         evidenceBundle,
		HistoricalScores: []float64{62, 68, 72, 75, 78},
		HistoricalTimes:  historicalTimes,
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
	cc61Evidence := reports.FilterEvidenceByProfile(evidenceBundle, "CC6.1")
	if err := gen.GenerateControlDetail(
		"examples/evidence-CC6.1.html",
		reports.FormatHTML,
		cc61Control,
		cc61Evidence,
	); err != nil {
		fmt.Fprintf(os.Stderr, "evidence detail: %v\n", err)
		os.Exit(1)
	}

	// Generate JSON report
	fmt.Println("Generating JSON report...")
	if err := gen.Generate(reports.ReportRequest{
		Type:       reports.ReportTypeReadiness,
		Format:     reports.FormatJSON,
		OutputPath: "examples/readiness-report.json",
	}, data); err != nil {
		fmt.Fprintf(os.Stderr, "JSON report: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Done. Generated:")
	fmt.Println("  examples/readiness-report.html")
	fmt.Println("  examples/executive-report.html")
	fmt.Println("  examples/evidence-CC6.1.html")
	fmt.Println("  examples/readiness-report.json")
}

func buildScanResults() *models.ScanResult {
	results := []models.CheckResult{
		// --- Customer-controlled checks (CIS 5.x) ---
		// RBAC checks — mixed results
		check("CIS-5.1.1", "Restrict cluster-admin ClusterRoleBinding usage", "CIS", "5.1", models.SeverityCritical, models.StatusPass,
			"Only 2 cluster-admin bindings found (system defaults)"),
		checkWithEvidence("CIS-5.1.2", "Minimize access to secrets", "CIS", "5.1", models.SeverityHigh, models.StatusFail,
			"3 roles grant get/list/watch on secrets: dev-team, monitoring, ci-deploy",
			[]models.Evidence{
				{Message: "Role grants secret access", Resource: models.Resource{Kind: "Role", Name: "dev-team", Namespace: "development"}},
				{Message: "Role grants secret access", Resource: models.Resource{Kind: "Role", Name: "monitoring", Namespace: "monitoring"}},
				{Message: "Role grants secret access", Resource: models.Resource{Kind: "Role", Name: "ci-deploy", Namespace: "ci"}},
			}),
		checkWithEvidence("CIS-5.1.3", "Minimize wildcard use in Roles and ClusterRoles", "CIS", "5.1", models.SeverityHigh, models.StatusFail,
			"2 ClusterRoles use wildcard resources: legacy-admin, dev-full-access",
			[]models.Evidence{
				{Message: "Wildcard resource permission", Resource: models.Resource{Kind: "ClusterRole", Name: "legacy-admin"}, Field: "rules[0].resources", Value: "*"},
				{Message: "Wildcard resource permission", Resource: models.Resource{Kind: "ClusterRole", Name: "dev-full-access"}, Field: "rules[0].resources", Value: "*"},
			}),
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
		checkWithEvidence("CIS-5.2.1", "Ensure allowPrivilegeEscalation is set to false", "CIS", "5.2", models.SeverityCritical, models.StatusFail,
			"4 containers allow privilege escalation in namespace: production",
			[]models.Evidence{
				{Message: "allowPrivilegeEscalation not set to false", Resource: models.Resource{Kind: "Pod", Name: "api-server-7f8d9", Namespace: "production"}, Field: "securityContext.allowPrivilegeEscalation"},
				{Message: "allowPrivilegeEscalation not set to false", Resource: models.Resource{Kind: "Pod", Name: "worker-3a2b1", Namespace: "production"}, Field: "securityContext.allowPrivilegeEscalation"},
				{Message: "allowPrivilegeEscalation not set to false", Resource: models.Resource{Kind: "Pod", Name: "scheduler-9c4d5", Namespace: "production"}, Field: "securityContext.allowPrivilegeEscalation"},
				{Message: "allowPrivilegeEscalation not set to false", Resource: models.Resource{Kind: "Pod", Name: "migrator-1e6f7", Namespace: "production"}, Field: "securityContext.allowPrivilegeEscalation"},
			}),
		check("CIS-5.2.2", "Ensure containers run as non-root", "CIS", "5.2", models.SeverityHigh, models.StatusPass,
			"All containers specify runAsNonRoot: true"),
		checkWithEvidence("CIS-5.2.3", "Minimize privileged containers", "CIS", "5.2", models.SeverityCritical, models.StatusFail,
			"1 privileged container: monitoring/node-exporter",
			[]models.Evidence{
				{Message: "Container runs in privileged mode", Resource: models.Resource{Kind: "Pod", Name: "node-exporter-k8s2x", Namespace: "monitoring"}, Field: "securityContext.privileged", Value: "true"},
			}),
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
		check("CIS-5.2.9", "Drop all capabilities", "CIS", "5.2", models.SeverityHigh, models.StatusPass,
			"All containers drop ALL capabilities"),
		check("CIS-5.2.10", "Ensure NET_RAW is not added", "CIS", "5.2", models.SeverityMedium, models.StatusPass,
			"No containers add NET_RAW"),
		check("CIS-5.2.11", "Ensure SYS_ADMIN is not added", "CIS", "5.2", models.SeverityCritical, models.StatusPass,
			"No containers add SYS_ADMIN"),
		check("CIS-5.2.12", "Minimize added capabilities", "CIS", "5.2", models.SeverityMedium, models.StatusPass,
			"Minimal capabilities added"),
		check("CIS-5.2.13", "Apply Seccomp profile", "CIS", "5.2", models.SeverityMedium, models.StatusPass,
			"RuntimeDefault seccomp profile applied"),

		// Network policies
		check("CIS-5.3.1", "Ensure CNI supports NetworkPolicy", "CIS", "5.3", models.SeverityHigh, models.StatusPass,
			"CNI supports NetworkPolicy (Calico detected)"),
		checkWithEvidence("CIS-5.3.2", "Ensure every namespace has a NetworkPolicy", "CIS", "5.3", models.SeverityHigh, models.StatusFail,
			"3 namespaces missing NetworkPolicy: staging, dev, monitoring",
			[]models.Evidence{
				{Message: "No NetworkPolicy defined", Resource: models.Resource{Kind: "Namespace", Name: "staging"}},
				{Message: "No NetworkPolicy defined", Resource: models.Resource{Kind: "Namespace", Name: "dev"}},
				{Message: "No NetworkPolicy defined", Resource: models.Resource{Kind: "Namespace", Name: "monitoring"}},
			}),

		// Secrets management
		checkWithEvidence("CIS-5.4.1", "Prefer using Secrets as files over environment variables", "CIS", "5.4", models.SeverityMedium, models.StatusFail,
			"8 pods reference secrets via environment variables",
			[]models.Evidence{
				{Message: "Secret referenced via env var", Resource: models.Resource{Kind: "Pod", Name: "api-server-7f8d9", Namespace: "production"}, Field: "env[DB_PASSWORD].valueFrom.secretKeyRef"},
			}),

		// General security
		check("CIS-5.7.1", "Create resource quota for namespaces", "CIS", "5.7", models.SeverityMedium, models.StatusWarn,
			"2 namespaces without resource quotas: dev, staging"),
		check("CIS-5.7.2", "Ensure Seccomp profile is set", "CIS", "5.7", models.SeverityMedium, models.StatusPass,
			"RuntimeDefault seccomp profile applied"),
		check("CIS-5.7.3", "Ensure security context is applied to pods and containers", "CIS", "5.7", models.SeverityHigh, models.StatusPass,
			"All pods have security context set"),
		check("CIS-5.7.4", "Ensure default namespace is not used", "CIS", "5.7", models.SeverityMedium, models.StatusPass,
			"No workloads in default namespace"),

		// --- Provider-managed checks (CIS 1.x, 2.x, 3.x, 4.x) ---
		providerManaged("CIS-1.2.1", "Ensure anonymous auth is disabled", "CIS", "1.2", models.SeverityCritical),
		providerManaged("CIS-1.2.2", "Ensure token auth file is not set", "CIS", "1.2", models.SeverityCritical),
		providerManaged("CIS-1.2.6", "Ensure authorization mode includes RBAC", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.7", "Ensure authorization mode excludes AlwaysAllow", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.8", "Ensure authorization mode includes Node", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.9", "Ensure EventRateLimit admission controller", "CIS", "1.2", models.SeverityMedium),
		providerManaged("CIS-1.2.14", "Ensure anonymous auth disabled", "CIS", "1.2", models.SeverityCritical),
		providerManaged("CIS-1.2.16", "Ensure audit logging enabled", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.17", "Ensure audit log maxage set", "CIS", "1.2", models.SeverityMedium),
		providerManaged("CIS-1.2.18", "Ensure audit log maxbackup set", "CIS", "1.2", models.SeverityMedium),
		providerManaged("CIS-1.2.19", "Ensure audit log maxsize set", "CIS", "1.2", models.SeverityMedium),
		providerManaged("CIS-1.2.20", "Ensure audit policy configured", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.21", "Ensure request timeout configured", "CIS", "1.2", models.SeverityMedium),
		providerManaged("CIS-1.2.23", "Ensure encryption at rest configured", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.24", "Ensure encryption providers configured", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.25", "Ensure TLS 1.2 minimum", "CIS", "1.2", models.SeverityHigh),
		providerManaged("CIS-1.2.26", "Ensure strong TLS ciphers", "CIS", "1.2", models.SeverityMedium),
		providerManaged("CIS-1.3.1", "Ensure terminated-pod-gc-threshold set", "CIS", "1.3", models.SeverityMedium),
		providerManaged("CIS-1.3.6", "Ensure service account credentials rotated", "CIS", "1.3", models.SeverityMedium),
		providerManaged("CIS-2.1", "Ensure etcd encryption configured", "CIS", "2.x", models.SeverityHigh),
		providerManaged("CIS-2.2", "Ensure etcd peer TLS enabled", "CIS", "2.x", models.SeverityHigh),
		providerManaged("CIS-2.4", "Ensure etcd peer cert auth", "CIS", "2.x", models.SeverityHigh),
		providerManaged("CIS-3.2", "Ensure audit policy covers key operations", "CIS", "3.x", models.SeverityHigh),
		providerManaged("CIS-4.2.1", "Ensure anonymous kubelet auth disabled", "CIS", "4.2", models.SeverityHigh),
		providerManaged("CIS-4.2.2", "Ensure kubelet authorization Webhook", "CIS", "4.2", models.SeverityHigh),
		providerManaged("CIS-4.2.3", "Ensure kubelet client TLS", "CIS", "4.2", models.SeverityHigh),
		providerManaged("CIS-4.2.4", "Ensure kubelet HTTPS", "CIS", "4.2", models.SeverityHigh),
		providerManaged("CIS-4.2.5", "Ensure kubelet streaming idle timeout", "CIS", "4.2", models.SeverityMedium),
		providerManaged("CIS-4.2.6", "Ensure protect kernel defaults", "CIS", "4.2", models.SeverityMedium),
		providerManaged("CIS-4.2.7", "Ensure iptables util chains", "CIS", "4.2", models.SeverityMedium),
		providerManaged("CIS-4.2.9", "Ensure event recording configured", "CIS", "4.2", models.SeverityMedium),
		providerManaged("CIS-4.2.12", "Ensure kubelet cert rotation", "CIS", "4.2", models.SeverityMedium),

		// --- NSA/CISA checks ---
		check("NSA-NS-1", "Ensure namespaces isolate workloads", "NSA-CISA", "Network Security", models.SeverityHigh, models.StatusPass,
			"Workloads properly isolated across namespaces"),
		check("NSA-NS-2", "Segment workloads by sensitivity", "NSA-CISA", "Network Security", models.SeverityMedium, models.StatusPass,
			"Namespaces segmented by environment"),
		checkWithEvidence("NSA-NS-3", "Restrict external network access", "NSA-CISA", "Network Security", models.SeverityHigh, models.StatusFail,
			"2 namespaces allow unrestricted egress",
			[]models.Evidence{
				{Message: "No egress NetworkPolicy", Resource: models.Resource{Kind: "Namespace", Name: "staging"}},
				{Message: "No egress NetworkPolicy", Resource: models.Resource{Kind: "Namespace", Name: "dev"}},
			}),
		check("NSA-PS-1", "Run containers as non-root", "NSA-CISA", "Pod Security", models.SeverityHigh, models.StatusPass,
			"All containers run as non-root"),
		check("NSA-PS-2", "Use read-only root filesystem", "NSA-CISA", "Pod Security", models.SeverityMedium, models.StatusPass,
			"Read-only root filesystems enforced"),
		check("NSA-PS-3", "Drop all capabilities", "NSA-CISA", "Pod Security", models.SeverityHigh, models.StatusPass,
			"Capabilities dropped"),
		checkWithEvidence("NSA-PS-4", "Prevent privilege escalation", "NSA-CISA", "Pod Security", models.SeverityCritical, models.StatusFail,
			"4 containers allow privilege escalation",
			[]models.Evidence{
				{Message: "Privilege escalation allowed", Resource: models.Resource{Kind: "Pod", Name: "api-server-7f8d9", Namespace: "production"}},
				{Message: "Privilege escalation allowed", Resource: models.Resource{Kind: "Pod", Name: "worker-3a2b1", Namespace: "production"}},
				{Message: "Privilege escalation allowed", Resource: models.Resource{Kind: "Pod", Name: "scheduler-9c4d5", Namespace: "production"}},
				{Message: "Privilege escalation allowed", Resource: models.Resource{Kind: "Pod", Name: "migrator-1e6f7", Namespace: "production"}},
			}),
		check("NSA-PS-8", "Set resource requests and limits", "NSA-CISA", "Pod Security", models.SeverityMedium, models.StatusPass,
			"Resource limits defined on all containers"),
		check("NSA-AA-1", "Configure strong authentication", "NSA-CISA", "Authentication", models.SeverityHigh, models.StatusPass,
			"OIDC authentication configured"),
		check("NSA-AA-2", "Implement MFA for cluster access", "NSA-CISA", "Authentication", models.SeverityMedium, models.StatusPass,
			"MFA enforced via identity provider"),
		check("NSA-AA-3", "Implement centralized identity", "NSA-CISA", "Authentication", models.SeverityMedium, models.StatusPass,
			"Centralized identity via OIDC"),
		check("NSA-AA-4", "Review and audit user access", "NSA-CISA", "Authentication", models.SeverityMedium, models.StatusPass,
			"Access review process in place"),
		check("NSA-AA-5", "Rotate service account tokens", "NSA-CISA", "Authentication", models.SeverityMedium, models.StatusPass,
			"Token rotation configured"),
		check("NSA-SC-1", "Use signed container images", "NSA-CISA", "Supply Chain", models.SeverityHigh, models.StatusPass,
			"Cosign signatures verified at admission"),
		check("NSA-SC-2", "Scan images for vulnerabilities", "NSA-CISA", "Supply Chain", models.SeverityHigh, models.StatusPass,
			"Trivy scanning integrated in CI/CD"),
		check("NSA-LM-1", "Enable audit logging", "NSA-CISA", "Logging", models.SeverityHigh, models.StatusPass,
			"Audit logging enabled via EKS"),
		check("NSA-LM-2", "Centralize log collection", "NSA-CISA", "Logging", models.SeverityMedium, models.StatusPass,
			"Logs shipped to CloudWatch + Datadog"),
		check("NSA-VM-1", "Implement vulnerability management", "NSA-CISA", "Vulnerability", models.SeverityHigh, models.StatusPass,
			"Vulnerability management process defined"),

		// --- PSS checks ---
		check("PSS-1.1", "Enforce Baseline Pod Security Standard", "PSS", "Pod Security", models.SeverityHigh, models.StatusPass,
			"Baseline PSS enforced on all non-system namespaces"),
		check("PSS-1.2", "Enforce Restricted Pod Security Standard", "PSS", "Pod Security", models.SeverityHigh, models.StatusWarn,
			"Restricted PSS enforced on 4 of 6 production namespaces"),
		check("PSS-1.3", "Enforce PSS via namespace labels", "PSS", "Pod Security", models.SeverityHigh, models.StatusPass,
			"pod-security.kubernetes.io/enforce labels applied"),
		check("PSS-2.1", "Enforce PSA at cluster level", "PSS", "Pod Security", models.SeverityMedium, models.StatusPass,
			"PSA configured cluster-wide"),
		check("PSS-2.2", "Enable PSA audit and warn modes", "PSS", "Pod Security", models.SeverityMedium, models.StatusPass,
			"Audit and warn modes enabled"),

		// --- RBAC checks ---
		check("RBAC-1", "Audit cluster-admin usage", "RBAC", "Access Control", models.SeverityHigh, models.StatusPass,
			"cluster-admin limited to break-glass accounts"),
		checkWithEvidence("RBAC-2", "Verify least-privilege role bindings", "RBAC", "Access Control", models.SeverityHigh, models.StatusFail,
			"3 overly permissive role bindings found",
			[]models.Evidence{
				{Message: "Overly permissive binding", Resource: models.Resource{Kind: "ClusterRoleBinding", Name: "dev-cluster-admin"}},
				{Message: "Overly permissive binding", Resource: models.Resource{Kind: "ClusterRoleBinding", Name: "ci-admin-binding"}},
				{Message: "Overly permissive binding", Resource: models.Resource{Kind: "RoleBinding", Name: "staging-admin", Namespace: "staging"}},
			}),
		checkWithEvidence("RBAC-3", "Remove wildcard permissions", "RBAC", "Access Control", models.SeverityHigh, models.StatusFail,
			"2 ClusterRoles use wildcard: legacy-admin, dev-full-access",
			[]models.Evidence{
				{Message: "Wildcard permissions", Resource: models.Resource{Kind: "ClusterRole", Name: "legacy-admin"}, Field: "rules[0].resources", Value: "*"},
				{Message: "Wildcard permissions", Resource: models.Resource{Kind: "ClusterRole", Name: "dev-full-access"}, Field: "rules[0].verbs", Value: "*"},
			}),
		check("RBAC-4", "Audit stale RoleBindings", "RBAC", "Access Control", models.SeverityMedium, models.StatusPass,
			"No stale bindings detected"),

		// --- Workload Hygiene ---
		check("WH-001", "Pin container images to digests", "Workload Hygiene", "Images", models.SeverityHigh, models.StatusPass,
			"All images pinned to SHA256 digests"),
		check("WH-002", "Set resource requests and limits", "Workload Hygiene", "Resources", models.SeverityMedium, models.StatusPass,
			"Resource limits set on all containers"),
		checkWithEvidence("WH-003", "Define liveness and readiness probes", "Workload Hygiene", "Health", models.SeverityMedium, models.StatusFail,
			"4 containers missing health probes",
			[]models.Evidence{
				{Message: "No liveness probe defined", Resource: models.Resource{Kind: "Deployment", Name: "batch-worker", Namespace: "workers"}},
				{Message: "No readiness probe defined", Resource: models.Resource{Kind: "Deployment", Name: "batch-worker", Namespace: "workers"}},
				{Message: "No liveness probe defined", Resource: models.Resource{Kind: "Deployment", Name: "cron-runner", Namespace: "workers"}},
				{Message: "No readiness probe defined", Resource: models.Resource{Kind: "Deployment", Name: "cron-runner", Namespace: "workers"}},
			}),
		check("WH-004", "Scale critical workloads to 2+ replicas", "Workload Hygiene", "Availability", models.SeverityMedium, models.StatusPass,
			"All critical workloads have 2+ replicas"),
		checkWithEvidence("WH-005", "Create PodDisruptionBudgets", "Workload Hygiene", "Availability", models.SeverityMedium, models.StatusFail,
			"3 multi-replica deployments lack PDBs",
			[]models.Evidence{
				{Message: "No PDB defined", Resource: models.Resource{Kind: "Deployment", Name: "api-server", Namespace: "production"}},
				{Message: "No PDB defined", Resource: models.Resource{Kind: "Deployment", Name: "web-frontend", Namespace: "production"}},
				{Message: "No PDB defined", Resource: models.Resource{Kind: "Deployment", Name: "event-processor", Namespace: "workers"}},
			}),

		// --- Supply Chain ---
		check("SC-001", "Add SBOM attestation", "Supply Chain", "Provenance", models.SeverityMedium, models.StatusPass,
			"SBOM attestations present on all images"),
		check("SC-002", "Sign container images", "Supply Chain", "Provenance", models.SeverityHigh, models.StatusPass,
			"All images signed with Cosign"),
		check("SC-003", "Deploy from approved registries only", "Supply Chain", "Provenance", models.SeverityHigh, models.StatusPass,
			"Registry allowlist enforced via admission"),

		// --- Ingress Hardening ---
		check("IH-001", "Configure TLS on Ingress resources", "Ingress", "TLS", models.SeverityHigh, models.StatusPass,
			"TLS configured on all Ingress resources"),
		checkWithEvidence("IH-002", "Create egress NetworkPolicies", "Ingress", "Egress", models.SeverityHigh, models.StatusFail,
			"2 namespaces without egress policies",
			[]models.Evidence{
				{Message: "No egress NetworkPolicy", Resource: models.Resource{Kind: "Namespace", Name: "staging"}},
				{Message: "No egress NetworkPolicy", Resource: models.Resource{Kind: "Namespace", Name: "dev"}},
			}),

		// --- Namespace Governance ---
		check("NG-001", "Create ResourceQuotas", "Namespace Gov", "Quotas", models.SeverityMedium, models.StatusWarn,
			"2 namespaces without ResourceQuotas"),
		checkWithEvidence("NG-002", "Create LimitRanges", "Namespace Gov", "Limits", models.SeverityMedium, models.StatusFail,
			"4 namespaces without LimitRanges",
			[]models.Evidence{
				{Message: "No LimitRange defined", Resource: models.Resource{Kind: "Namespace", Name: "staging"}},
				{Message: "No LimitRange defined", Resource: models.Resource{Kind: "Namespace", Name: "dev"}},
				{Message: "No LimitRange defined", Resource: models.Resource{Kind: "Namespace", Name: "monitoring"}},
				{Message: "No LimitRange defined", Resource: models.Resource{Kind: "Namespace", Name: "logging"}},
			}),
		check("NG-003", "Apply standard Kubernetes labels", "Namespace Gov", "Labels", models.SeverityLow, models.StatusPass,
			"Standard labels applied to all resources"),

		// --- API Hygiene ---
		check("AH-001", "Migrate deprecated APIs", "API Hygiene", "Deprecation", models.SeverityMedium, models.StatusPass,
			"No deprecated API versions in use"),
		check("AH-002", "Evaluate alpha/beta API usage", "API Hygiene", "Stability", models.SeverityLow, models.StatusPass,
			"No alpha APIs in use; 1 beta API (autoscaling/v2beta2) under review"),
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

func checkWithEvidence(id, name, benchmark, section string, severity models.Severity, status models.CheckStatus, msg string, evidence []models.Evidence) models.CheckResult {
	return models.CheckResult{
		ID:        id,
		Name:      name,
		Benchmark: benchmark,
		Section:   section,
		Severity:  severity,
		Status:    status,
		Message:   msg,
		Evidence:  evidence,
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
	mapper := compliance.NewSOC2Mapper()
	return mapper.MapResults(scan)
}

func buildEvidence() *evidence.EvidenceBundle {
	ts := time.Date(2026, 3, 7, 14, 29, 47, 0, time.UTC)
	return &evidence.EvidenceBundle{
		CollectedAt: ts,
		ClusterName: "prod-eks-us-east-1",
		Items: []evidence.EvidenceItem{
			{
				Category:    "RBAC",
				Type:        "rbac-cluster-admin",
				Description: "RBAC ClusterRoleBinding inventory and cluster-admin scope",
				Timestamp:   ts,
				SHA256:      "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
				Data: evidence.RBACSnapshot{
					ClusterRoleCount:        47,
					ClusterRoleBindingCount: 23,
					RoleCount:               31,
					RoleBindingCount:        93,
					ServiceAccountCount:     58,
					ClusterAdminBindings: []evidence.AdminBinding{
						{Name: "system:masters-binding", Subject: "system:masters", Type: "Group"},
						{Name: "eks-admin-binding", Subject: "break-glass-admin", Type: "User"},
					},
					WildcardRoles: []string{"legacy-admin", "dev-full-access"},
				},
			},
			{
				Category:    "RBAC",
				Type:        "rbac-sa-token-mount",
				Description: "Service account token mount audit across 12 namespaces",
				Timestamp:   ts.Add(time.Second),
				SHA256:      "b2c3d4e5f6a7890abcdef1234567890abcdef1234567890abcdef1234567890ab",
				Data: evidence.SATokenMountSnapshot{
					NamespacesAudited: 12,
					AutoMountCount:    0,
				},
			},
			{
				Category:    "RBAC",
				Type:        "rbac-namespace-scope",
				Description: "Namespace scope ratio: 80% namespace-scoped",
				Timestamp:   ts.Add(time.Second),
				SHA256:      "c3d4e5f6a7b890abcdef1234567890abcdef1234567890abcdef1234567890abc",
				Data: evidence.NamespaceScopeSnapshot{
					TotalRoleBindings:      116,
					NamespaceScopedCount:   93,
					ClusterScopedCount:     23,
					NamespaceScopedPercent: 80,
				},
			},
			{
				Category:    "Network",
				Type:        "network-policy-coverage",
				Description: "NetworkPolicy coverage: 18 policies across 9 namespaces",
				Timestamp:   ts.Add(2 * time.Second),
				SHA256:      "d4e5f6a7b8c90abcdef1234567890abcdef1234567890abcdef1234567890abcd",
				Data: evidence.NetworkSnapshot{
					TotalPolicies: 18,
					NamespaceSummaries: []evidence.NamespacePolicySummary{
						{Namespace: "production", PolicyCount: 4, HasIngress: true, HasEgress: true},
						{Namespace: "api", PolicyCount: 3, HasIngress: true, HasEgress: true},
						{Namespace: "workers", PolicyCount: 2, HasIngress: true, HasEgress: false},
						{Namespace: "data", PolicyCount: 3, HasIngress: true, HasEgress: true},
						{Namespace: "monitoring", PolicyCount: 2, HasIngress: true, HasEgress: false},
						{Namespace: "logging", PolicyCount: 1, HasIngress: true, HasEgress: false},
						{Namespace: "kube-system", PolicyCount: 1, HasIngress: true, HasEgress: false},
						{Namespace: "cert-manager", PolicyCount: 1, HasIngress: false, HasEgress: true},
						{Namespace: "ingress-nginx", PolicyCount: 1, HasIngress: true, HasEgress: true},
					},
				},
			},
			{
				Category:    "Network",
				Type:        "default-deny-status",
				Description: "Default-deny status: 7 of 12 namespaces have default-deny policies",
				Timestamp:   ts.Add(2 * time.Second),
				SHA256:      "e5f6a7b8c9d0abcdef1234567890abcdef1234567890abcdef1234567890abcde",
				Data: evidence.DefaultDenySnapshot{
					TotalNamespaces:       12,
					NamespacesWithDeny:    7,
					NamespacesWithoutDeny: []string{"staging", "dev", "monitoring", "logging", "default"},
				},
			},
			{
				Category:    "Audit",
				Type:        "audit-logging",
				Description: "Audit logging: API server not found (managed cluster)",
				Timestamp:   ts.Add(3 * time.Second),
				SHA256:      "f6a7b8c9d0e1abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Data: evidence.AuditSnapshot{
					APIServerFound: false,
				},
			},
			{
				Category:    "Encryption",
				Type:        "encryption-tls",
				Description: "Encryption: etcd not found (managed cluster)",
				Timestamp:   ts.Add(3 * time.Second),
				SHA256:      "a7b8c9d0e1f2abcdef1234567890abcdef1234567890abcdef1234567890abcde0",
				Data: evidence.EncryptionSnapshot{
					EtcdFound: false,
				},
			},
		},
	}
}
