# Varax Compliance Automation Platform — Product Requirements Document

**Version**: 3.0
**Last Updated**: February 2026
**Status**: Active Development
**Build Timeline**: v1 in ~14 weeks (operator + CLI reports), v2 TBD (SaaS dashboard)
**Target Revenue**: $3,000 MRR within 12 months
**Framework Focus (v1)**: SOC2 only (HIPAA/PCI-DSS added in v2)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [What Changed Since v2.0](#what-changed-since-v20)
3. [The Problem](#the-problem)
4. [The Solution](#the-solution)
5. [Market Analysis](#market-analysis)
6. [Competitive Landscape](#competitive-landscape)
7. [Customer Personas](#customer-personas)
8. [Product Phases Overview](#product-phases-overview)
9. [v1 Architecture: Operator + CLI Reports](#v1-architecture-operator--cli-reports)
10. [Repository: varax-operator (v1)](#repository-varax-operator-v1)
11. [CLI Report Generator](#cli-report-generator)
12. [Compliance Framework Mapping (SOC2)](#compliance-framework-mapping-soc2)
13. [Prometheus Metrics](#prometheus-metrics)
14. [Helm Chart](#helm-chart)
15. [RBAC & Security](#rbac--security)
16. [v2 Architecture: SaaS Dashboard (Future)](#v2-architecture-saas-dashboard-future)
17. [Pricing & Business Model](#pricing--business-model)
18. [Go-to-Market Strategy](#go-to-market-strategy)
19. [Development Phases (v1)](#development-phases-v1)
20. [Consulting Hybrid Model](#consulting-hybrid-model)
21. [Open Source Strategy](#open-source-strategy)
22. [Risk Analysis](#risk-analysis)
23. [Success Metrics](#success-metrics)
24. [Relationship to k8s-cronjob-monitor](#relationship-to-k8s-cronjob-monitor)

---

## Executive Summary

**Product Name**: Varax
**Tagline**: "Automated Kubernetes compliance for SOC2 — scan, evidence, report"
**Business Model**: Open-source operator (Apache 2.0) with commercial CLI report generation and future SaaS dashboard
**Primary Market**: B2B SaaS companies (50–500 employees) running Kubernetes who need SOC2 certification

Varax is a Kubernetes-native compliance automation platform. **v1** is a single Go binary: an operator that continuously scans clusters for security violations, auto-enables audit logging, and generates audit-ready HTML/PDF compliance reports directly from the CLI. No SaaS backend, no web dashboard, no external dependencies.

**v2** (built after v1 proves product-market fit with paying customers) adds a SaaS dashboard with multi-cluster aggregation, evidence management, and a visual compliance workflow.

### Why This Architecture

The original v2.0 PRD planned a three-repository system (Go operator, Python API, TypeScript frontend) built over 24 weeks. Research into solo founder execution patterns revealed this was high-risk:

- **30% of solo SaaS products never reach $1K MRR**
- **Enterprise sales without SOC2 certification of your own is nearly impossible**
- **ARMO/Kubescape has $30M funding and 83 engineers — you need speed, not feature parity**

The revised approach ships a usable, sellable product in ~14 weeks instead of 24, gets real customer feedback before investing in SaaS infrastructure, and keeps the full SaaS vision as a funded v2 expansion.

### Why SOC2 Only (v1)

- **Most common ask**: 83% of enterprise buyers require SOC2 before vendor onboarding
- **Flexible framework**: You define your own controls (unlike rigid HIPAA/PCI)
- **Broadest buyer base**: Every SaaS company selling to enterprises needs SOC2
- **Reachable buyers**: DevOps teams at Series A–C startups, not enterprise procurement
- **40% less build scope**: One framework mapping instead of three

HIPAA and PCI-DSS are added in v2 as expansion revenue drivers once the SOC2 foundation is proven.

---

## What Changed Since v2.0

| Aspect | v2.0 PRD | v3.0 PRD (this document) |
|--------|----------|--------------------------|
| **Repositories** | 3 (Go operator, Python API, TypeScript frontend) | 1 (Go operator with embedded CLI report generator) |
| **Build timeline** | 24 weeks (6 phases) | ~14 weeks for v1; v2 TBD after customer validation |
| **Frameworks at launch** | SOC2 + HIPAA + PCI-DSS | SOC2 only |
| **Report delivery** | SaaS dashboard + PDF download | CLI-generated HTML/PDF directly from operator |
| **Dependencies** | PostgreSQL, TimescaleDB, Redis, Celery, S3 | None (self-contained Go binary) |
| **Revenue model** | Free operator → paid SaaS dashboard | Free operator → paid license key ($149/mo or $1,490/yr) → paid SaaS dashboard (v2) |
| **First revenue** | Month 6 (after building full SaaS) | Month 4 (Pro license + consulting) |
| **Primary risk** | Over-building before validation | Under-building (mitigated by clear v2 path) |
| **Enterprise tier** | $999–$2,999/month from Month 7 | Deferred to v2; v1 focuses on self-serve Pro |
| **Hosting costs** | Render (API + DB + frontend) | $0 (runs in customer's cluster) |
| **Pricing** | $199/month Pro, $999+ Enterprise | $149/mo or $1,490/yr Pro (v1), $199+ SaaS (v2) |

---

## The Problem

Companies running Kubernetes face severe compliance challenges:

### 1. Audit Logs Disabled by Default
- **EKS (AWS)**: Control plane audit logging is disabled by default; must be explicitly enabled per cluster
- **AKS (Azure)**: Diagnostic settings for audit logging require manual configuration
- **GKE (Google)**: Admin Activity logs enabled by default, but Data Access logs are not
- Companies running without audit logs are blind to security events and fail compliance audits immediately

### 2. Manual Evidence Collection
- Teams spend weeks collecting screenshots and configuration dumps before each audit
- Proving RBAC policies, encryption status, network policies is tedious and error-prone
- Auditors increasingly want continuous proof, not point-in-time snapshots
- Evidence goes stale between collection and audit review

### 3. Unknown Compliance Gaps
- Pod Security Standards not enforced
- Secrets stored in container images or environment variables
- Overly permissive RBAC (ClusterAdmin for everyone)
- No encryption at rest for etcd
- Teams don't know what's missing until an audit fails

### 4. Existing Tools Don't Close the Loop
- **Kubescape** scans and gives terminal output — but doesn't generate auditor-ready evidence
- **Vanta/Drata** ($10K–$50K/year) automate general compliance but treat Kubernetes as a black box
- **DIY Prometheus + kube-bench** requires stitching together multiple tools with no compliance mapping

### The Cost of Not Solving This
- **Failed SOC2 audit**: Lose enterprise deals, 6-month remediation delay
- **Manual evidence collection**: 100–500 hours per audit cycle ($15K–$75K in engineer time)
- **Data breach average cost**: $4.88M (2024 IBM report)
- **SOC2 Type II audit fees**: $30K–$100K+ per cycle

---

## The Solution

Varax automates Kubernetes SOC2 compliance through three capabilities, delivered as a **single Go binary** that runs in the customer's cluster:

### 1. Auto-Enable Audit Logging
The operator detects the cloud provider (EKS, AKS, GKE, self-hosted) and programmatically enables comprehensive audit logging. No manual configuration beyond installing the Helm chart.

| Provider | Detection | API Action |
|----------|-----------|------------|
| **EKS** | Node labels `eks.amazonaws.com` | `UpdateClusterConfig` via AWS SDK |
| **AKS** | Node labels `kubernetes.azure.com` | Create diagnostic settings via Azure SDK |
| **GKE** | Node labels `cloud.google.com` | Verify/enable Data Access logs via GCP SDK |
| **Self-hosted** | Fallback | Create ConfigMap with audit policy; notify user |

### 2. Continuous Compliance Scanning
Continuously scans cluster resources against:
- **CIS Kubernetes Benchmark 1.8+**: 120+ security checks
- **NSA/CISA Kubernetes Hardening Guide**: Infrastructure-level hardening
- **Pod Security Standards** (Baseline, Restricted): Workload security
- **Custom policies via OPA**: Organization-specific rules

All scan results are mapped to SOC2 Trust Services Criteria controls.

### 3. Audit-Ready Report Generation (CLI)
The operator includes a built-in report generator invoked via CLI:

```bash
# Generate SOC2 readiness report as HTML
varax report --framework soc2 --format html --output report.html

# Generate SOC2 readiness report as PDF
varax report --framework soc2 --format pdf --output report.pdf

# Generate executive summary
varax report --framework soc2 --type executive --format pdf

# Generate evidence package for a specific control
varax evidence --control CC6.1 --format html
```

Reports include:
- Overall compliance score with pass/fail breakdown
- Per-control status with evidence (RBAC snapshots, encryption validation, network policies)
- Remediation instructions for each failing check
- Timestamp and cluster metadata for audit trail
- Historical trend data (stored locally in operator's PVC)

**This is the key differentiator**: Kubescape tells you what's wrong. Varax generates the PDF your auditor needs.

---

## Market Analysis

### Total Addressable Market (TAM)
- **SOC2 automation tools market**: Growing from ~$850M (2025) to projected $2.7B by 2028
- **Kubernetes adoption**: 96% of enterprises use or evaluate Kubernetes for production; 63% of deployments use managed services
- **Compliance spend**: Companies spend $30K–$150K+ annually on SOC2 alone

### Serviceable Addressable Market (SAM)
Companies running Kubernetes that need SOC2:
- ~50,000 companies running Kubernetes in production
- ~30% need SOC2 certification = 15,000 companies
- Average spend: $50K–$100K/year on compliance

### Serviceable Obtainable Market (SOM) — Year 1
Realistic first-year capture with open-source strategy:
- 500–1,000 open-source installations
- 20–40 paid Pro customers (CLI reports)
- 2–5 consulting engagements
- Target: $3K–$5K MRR

### Market Validation
The compliance automation landscape (Vanta, Drata, Secureframe) validates massive demand. Varax targets the **Kubernetes-specific compliance gap** these platforms don't address deeply. It's a **complement** to Vanta/Drata, not a competitor.

The 2026 Kubernetes market increasingly demands compliance by design — teams rely on policy-as-code and automated reporting to show which workloads meet specific controls. Varax is positioned exactly at this intersection.

---

## Competitive Landscape

### General Compliance Platforms (Different Market — Complement)

| Platform | Annual Cost | K8s Depth | Our Position |
|----------|------------|-----------|--------------|
| **Vanta** | $10K–$50K+ | Shallow (cloud account level) | Complement — we provide deep K8s evidence they can't |
| **Drata** | $7.5K–$40K+ | Shallow | Complement |
| **Secureframe** | $6K–$25K+ | Shallow | Complement |

### Kubernetes Security Tools (Overlap)

| Tool | Model | Compliance Focus | Our Differentiation |
|------|-------|-----------------|---------------------|
| **Kubescape (ARMO)** | OSS + Commercial ($30M funding, 83 employees, CNCF incubating) | CIS, NSA, MITRE, SOC2 scanning | Most direct competitor. They scan and score. We scan, score, AND generate the auditor-ready report with evidence. Their pricing is per-node/vCPU (opaque). Ours is flat-rate (transparent). |
| **Fairwinds Insights** | Commercial SaaS | CIS, governance | Enterprise-focused managed K8s. We're self-installable, targeting smaller teams |
| **Trivy (Aqua)** | OSS | Vulnerability + misconfiguration scanning | Scanner only, no compliance reporting or evidence |
| **Kyverno** | OSS | Policy enforcement | Policy engine, not compliance platform. Complementary |
| **Prisma Cloud** | Enterprise | Full-stack cloud security | $100K+ pricing, overkill for compliance-only |

### Our Unique Position

1. **Auto-enable audit logging** — No other OSS tool does this programmatically across cloud providers
2. **Auditor-ready reports from CLI** — Not just scan results; actual evidence packages mapped to SOC2 controls
3. **Zero external dependencies** — Single binary, runs in cluster, no SaaS required
4. **Flat-rate transparent pricing** — Not per-node like ARMO
5. **Complement to Vanta/Drata** — Works alongside existing compliance platforms

---

## Customer Personas

### Primary: DevOps/Platform Engineer at a Scale-Up (50–500 employees)

**Profile**: Sarah, Senior DevOps Engineer at a B2B SaaS company
**Context**: Company just signed their first enterprise client who requires SOC2 Type II
**Pain**: "Our CTO asked me to get us SOC2 compliant. I know Kubernetes, but I have no idea what controls we're missing or how to prove compliance to an auditor."
**Budget**: $100–$500/month (can expense on corporate card without procurement)
**Buying behavior**: Finds tools on GitHub, tries free tier, upgrades if it saves time
**Why v1 works for her**: Install operator → run `varax report` → hand PDF to auditor. No SaaS signup needed.

### Secondary: CTO/VP Engineering at Early-Stage Startup (10–50 employees)

**Profile**: Marcus, CTO at a Series A startup
**Context**: Enterprise prospects keep asking for SOC2 before signing deals
**Pain**: "We're losing deals because we can't prove compliance. Vanta wants $15K/year and still doesn't cover our Kubernetes infrastructure deeply."
**Budget**: $100–$300/month
**Buying behavior**: Wants self-serve, hates sales calls, will pay for something that "just works"
**Why v1 works for him**: Flat monthly fee, installs in 60 seconds, generates the report his prospects need.

### Tertiary (v2): Security/Compliance Engineer at Mid-Market

**Profile**: Priya, Security Engineer managing compliance across 15+ clusters
**Pain**: "I spend 3 months each year collecting evidence manually."
**Why she needs v2**: Multi-cluster aggregation dashboard, evidence timeline, team collaboration
**Budget**: $500–$2,000/month (v2 pricing)

---

## Product Phases Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Varax Product Evolution             │
│                                                                   │
│  v1: Operator + CLI Reports (~14 weeks)                          │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ • Single Go binary (operator + report generator)            │ │
│  │ • SOC2 framework only                                       │ │
│  │ • CIS/NSA/PSS scanning → SOC2 control mapping             │ │
│  │ • Auto-enable audit logging (EKS/AKS/GKE)                 │ │
│  │ • CLI: varax report --format pdf                       │ │
│  │ • HTML/PDF reports with evidence                            │ │
│  │ • Prometheus metrics                                        │ │
│  │ • Helm chart installation                                   │ │
│  │ • FREE: Operator + basic CLI report                        │ │
│  │ • PRO ($99-149/mo): Full reports + evidence packages       │ │
│  └─────────────────────────────────────────────────────────────┘ │
│         │                                                         │
│         │ After v1 proves PMF with paying customers               │
│         ▼                                                         │
│  v2: SaaS Dashboard (timeline TBD, ~10-12 weeks additional)      │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ • FastAPI backend + Next.js frontend (2 new repos)         │ │
│  │ • HIPAA + PCI-DSS framework support                        │ │
│  │ • Multi-cluster aggregation dashboard                       │ │
│  │ • Evidence library with timeline view                       │ │
│  │ • Manual evidence upload                                    │ │
│  │ • Team collaboration features                               │ │
│  │ • Report wizard UI                                          │ │
│  │ • Historical trend analysis                                 │ │
│  │ • PRO ($199/mo): SaaS dashboard access                    │ │
│  │ • ENTERPRISE ($999+/mo): SSO, multi-cluster, SLA          │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## v1 Architecture: Operator + CLI Reports

```
┌──────────────────────────────────────────────────────────────────┐
│              Customer's Kubernetes Cluster                         │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Varax Operator (Single Go Binary)                    │    │
│  │                                                             │    │
│  │  ┌─────────────────────────────────────────────────────┐  │    │
│  │  │  Compliance Scanner                                  │  │    │
│  │  │  • CIS Benchmark 1.8 (120+ checks)                 │  │    │
│  │  │  • NSA/CISA Hardening Guide                        │  │    │
│  │  │  • Pod Security Standards                           │  │    │
│  │  │  • RBAC Analyzer                                    │  │    │
│  │  │  • OPA Custom Policies                              │  │    │
│  │  │  → All mapped to SOC2 controls                      │  │    │
│  │  └─────────────────────────────────────────────────────┘  │    │
│  │                                                             │    │
│  │  ┌─────────────────────────────────────────────────────┐  │    │
│  │  │  Audit Log Enabler                                   │  │    │
│  │  │  • Auto-detect EKS/AKS/GKE/self-hosted             │  │    │
│  │  │  • Enable via cloud provider SDK                    │  │    │
│  │  │  • Validate logs are flowing                        │  │    │
│  │  └─────────────────────────────────────────────────────┘  │    │
│  │                                                             │    │
│  │  ┌─────────────────────────────────────────────────────┐  │    │
│  │  │  Report Generator (Embedded)                         │  │    │
│  │  │  • Go html/template → HTML reports                  │  │    │
│  │  │  • chromedp or go-wkhtmltopdf → PDF conversion      │  │    │
│  │  │  • Glamour → Rich terminal reports                  │  │    │
│  │  │  • Evidence snapshots (RBAC, network, encryption)   │  │    │
│  │  │  • SOC2 control mapping with pass/fail/evidence     │  │    │
│  │  └─────────────────────────────────────────────────────┘  │    │
│  │                                                             │    │
│  │  ┌─────────────────────────────────────────────────────┐  │    │
│  │  │  CLI Experience (Charm Suite)                        │  │    │
│  │  │  • Cobra: command structure + shell completions     │  │    │
│  │  │  • Lipgloss: styled output, badges, gauges, boxes  │  │    │
│  │  │  • Bubble Tea: scan progress, interactive explorer  │  │    │
│  │  │  • Dual-mode: styled (TTY) + JSON (CI/CD)          │  │    │
│  │  └─────────────────────────────────────────────────────┘  │    │
│  │                                                             │    │
│  │  ┌─────────────────────────────────────────────────────┐  │    │
│  │  │  Metrics Exporter                                    │  │    │
│  │  │  • Prometheus endpoint :8080/metrics                │  │    │
│  │  │  • Compliance scores, violations, control status    │  │    │
│  │  └─────────────────────────────────────────────────────┘  │    │
│  │                                                             │    │
│  │  ┌─────────────────────────────────────────────────────┐  │    │
│  │  │  Local Storage (PVC)                                 │  │    │
│  │  │  • Scan history (SQLite or BoltDB)                  │  │    │
│  │  │  • Evidence snapshots over time                     │  │    │
│  │  │  • Trend data for reports                           │  │    │
│  │  └─────────────────────────────────────────────────────┘  │    │
│  └──────────────────────────────────────────────────────────┘    │
│         │                                                          │
│         │ :8080/metrics                                            │
│         ▼                                                          │
│  Prometheus (user's existing) → Grafana → AlertManager             │
└────────────────────────────────────────────────────────────────────┘

No external dependencies. No SaaS. No database server. Everything in-cluster.
```

### Technology Stack (v1)

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Operator** | Go | 1.22+ | Single binary: operator + CLI |
| **Operator Framework** | Kubebuilder | 3.14+ | CRD scaffolding |
| **Controller Runtime** | controller-runtime | v0.17+ | Reconciliation loops |
| **K8s Client** | client-go | v0.30+ | Kubernetes API access |
| **Policy Engine** | OPA | v0.61+ | Custom policy evaluation |
| **CLI Framework** | Cobra (spf13/cobra) | v1.8+ | Command structure, flags, subcommands, shell completions |
| **CLI Styling** | Lipgloss (charmbracelet/lipgloss) | v0.10+ | CSS-like terminal styling: colors, borders, alignment, adaptive themes |
| **CLI Interactivity** | Bubble Tea (charmbracelet/bubbletea) | v0.25+ | Interactive TUI: real-time scan progress, drill-down views |
| **CLI Components** | Bubbles (charmbracelet/bubbles) | Latest | Pre-built TUI components: spinners, progress bars, tables |
| **CLI Markdown** | Glamour (charmbracelet/glamour) | Latest | Styled markdown rendering in terminal for rich report output |
| **Report Templates** | Go html/template | stdlib | HTML report rendering |
| **PDF Conversion** | chromedp or go-wkhtmltopdf | Latest | HTML → PDF |
| **Local Storage** | BoltDB (bbolt) | Latest | Scan history, evidence snapshots |
| **Metrics** | prometheus/client_golang | v1.19+ | Prometheus metrics |
| **Logging** | zap | v1.27+ | Structured logging |
| **Cloud SDKs** | AWS SDK v2, Azure SDK, GCP SDK | Latest | Audit log enablement |
| **License Validation** | Ed25519 signatures | stdlib (crypto/ed25519) | Pro license key verification (offline, no phone-home) |

**What's NOT in v1**: No Python. No TypeScript. No PostgreSQL. No Redis. No Celery. No S3. No web frontend.

**CLI Library Philosophy**: The Charm suite (Lipgloss, Bubble Tea, Bubbles, Glamour) provides a cohesive visual aesthetic across all CLI output. Because they come from the same team, colors, border styles, and spacing are consistent — the CLI feels *designed*, not cobbled together. This matters because the CLI **is** the product experience in v1. DevOps engineers notice and share well-crafted terminal tools.

---

## Repository: varax-operator (v1)

**License**: Apache 2.0 (Open Source) — with Pro features gated by license key
**Single repository**: Everything lives here for v1.

### Directory Structure

```
varax-operator/
├── cmd/
│   └── varax/
│       ├── main.go                          # Entry point (operator mode + CLI mode)
│       ├── operator.go                      # Start operator (default)
│       ├── report.go                        # CLI: varax report
│       ├── evidence.go                      # CLI: varax evidence
│       ├── scan.go                          # CLI: varax scan (one-shot)
│       └── version.go                       # CLI: varax version
├── api/
│   └── v1alpha1/
│       ├── complianceconfig_types.go        # CRD: ComplianceConfig
│       └── zz_generated.deepcopy.go
├── controllers/
│   ├── complianceconfig_controller.go       # Main reconciler
│   ├── audit_enabler.go                     # Auto-enable audit logs
│   └── security_scanner.go                  # Orchestrates all scanners
├── pkg/
│   ├── providers/
│   │   ├── detect.go                        # Cloud provider auto-detection
│   │   ├── provider.go                      # Provider interface
│   │   ├── aws/
│   │   │   └── eks_audit.go                 # EKS audit logging via AWS SDK
│   │   ├── azure/
│   │   │   └── aks_audit.go                 # AKS diagnostic settings
│   │   ├── gcp/
│   │   │   └── gke_audit.go                 # GKE Cloud Logging verification
│   │   └── selfhosted/
│   │       └── audit_policy.go              # Generic K8s audit policy
│   ├── scanning/
│   │   ├── cis_benchmark.go                 # CIS Kubernetes Benchmark 1.8
│   │   ├── nsa_hardening.go                 # NSA/CISA hardening guide
│   │   ├── pod_security.go                  # PSS/PSA checks
│   │   ├── rbac_analyzer.go                 # RBAC least privilege analysis
│   │   ├── scanner.go                       # Scanner orchestrator
│   │   └── checks/                          # Individual check implementations
│   │       ├── cis_5_1_rbac.go
│   │       ├── cis_5_2_pod_security.go
│   │       └── ...
│   ├── compliance/
│   │   ├── soc2_controls.go                 # SOC2 Trust Services Criteria mapping
│   │   ├── mapper.go                        # Map scan results → SOC2 controls
│   │   └── scorer.go                        # Compliance score calculation
│   ├── evidence/
│   │   ├── collector.go                     # Collect evidence snapshots
│   │   ├── rbac_snapshot.go                 # RBAC state capture
│   │   ├── network_snapshot.go              # NetworkPolicy state capture
│   │   ├── encryption_check.go              # Encryption validation
│   │   └── audit_log_proof.go               # Audit logging validation
│   ├── reports/
│   │   ├── generator.go                     # Report orchestrator
│   │   ├── html_renderer.go                 # Go template → HTML
│   │   ├── pdf_converter.go                 # HTML → PDF
│   │   ├── templates/
│   │   │   ├── soc2_readiness.html          # Full SOC2 readiness report
│   │   │   ├── soc2_executive.html          # Executive summary
│   │   │   ├── control_detail.html          # Per-control evidence page
│   │   │   ├── base.html                    # Shared layout
│   │   │   └── styles.css                   # Embedded report styles
│   │   └── assets/
│   │       └── logo.png                     # Varax branding
│   ├── cli/
│   │   ├── styles.go                        # Lipgloss style definitions (colors, borders, badges)
│   │   ├── theme.go                         # Adaptive light/dark terminal theme
│   │   ├── score_gauge.go                   # Compliance score visual gauge (colored bar)
│   │   ├── control_table.go                 # Styled control status table (PASS/FAIL/PARTIAL badges)
│   │   ├── scan_progress.go                 # Bubble Tea real-time scan progress with spinner
│   │   ├── summary_box.go                   # Bordered summary box for post-scan output
│   │   ├── deploy_validation.go             # Post-install "aha moment" output
│   │   └── json_output.go                   # Machine-readable JSON output for --output json
│   ├── metrics/
│   │   ├── exporter.go                      # Prometheus metrics endpoint
│   │   └── collector.go                     # Metric collection
│   ├── storage/
│   │   ├── store.go                         # BoltDB interface
│   │   ├── scan_history.go                  # Historical scan results
│   │   └── evidence_store.go               # Evidence snapshots over time
│   ├── licensing/
│   │   ├── license.go                       # License key validation
│   │   └── features.go                      # Feature gating (free vs pro)
│   ├── remediation/
│   │   ├── auto_fixer.go                    # Safe auto-remediation (opt-in)
│   │   └── actions.go                       # Specific fix implementations
│   └── models/
│       ├── compliance_result.go             # Scan result models
│       ├── evidence.go                      # Evidence data structures
│       └── report.go                        # Report data models
├── helm/
│   └── varax/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── deployment.yaml
│           ├── service.yaml
│           ├── servicemonitor.yaml
│           ├── rbac.yaml
│           ├── pvc.yaml                     # Persistent storage for scan history
│           ├── crd-complianceconfig.yaml
│           └── NOTES.txt
├── config/
│   ├── crd/
│   ├── rbac/
│   └── samples/
│       └── complianceconfig-soc2.yaml
├── docs/
│   ├── installation.md
│   ├── architecture.md
│   ├── reports.md                           # Report format documentation
│   ├── security.md
│   └── soc2-controls.md                     # SOC2 mapping reference
├── examples/
│   ├── sample-report.html                   # Example generated report
│   └── sample-report.pdf
├── hack/
│   └── test-setup.sh                        # Local testing with kind
├── .github/
│   ├── workflows/
│   │   ├── ci.yaml
│   │   ├── release.yaml
│   │   └── docker-build.yaml
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
├── LICENSE                                  # Apache 2.0
├── CONTRIBUTING.md
└── README.md
```

### Custom Resource Definition

```yaml
apiVersion: compliance.varax.io/v1alpha1
kind: ComplianceConfig
metadata:
  name: default
  namespace: varax-system
spec:
  # Compliance framework (v1: SOC2 only)
  framework: soc2
  controls:
    - CC6.1   # Logical and physical access controls
    - CC6.2   # System credentials management
    - CC6.3   # Access removal
    - CC6.6   # System boundaries protection
    - CC6.8   # Vulnerability management
    - CC7.1   # Detect unauthorized changes
    - CC7.2   # Monitor system components
    - CC7.3   # Evaluate security events
    - CC8.1   # Restrict sensitive information

  # Scanning configuration
  scanning:
    interval: 1h
    namespaces:
      include: ["*"]
      exclude: ["kube-system"]
    benchmarks:
      - cis-1.8
      - nsa-hardening
      - pod-security-restricted

  # Audit logging
  auditLogging:
    autoEnable: true
    retentionDays: 395              # 13 months for SOC2
    level: RequestResponse

  # Remediation (opt-in)
  remediation:
    autoFix: false
    dryRun: true
    allowedActions:
      - addResourceLimits
      - disableServiceAccountAutoMount
      - addNetworkPolicies
      - enforcePodSecurityStandards

  # Report configuration
  reports:
    retention: 90d                  # Keep generated reports for 90 days
    autoGenerate: false             # Generate reports on schedule (Pro)
    schedule: "0 0 1 * *"          # Monthly (if autoGenerate: true)

  # Alert configuration
  alerts:
    slack:
      enabled: false
      webhookUrl:
        secretRef:
          name: slack-webhook
          key: url

status:
  phase: Ready
  lastScanTime: "2026-02-28T10:00:00Z"
  complianceScore: 87.5
  violationCount: 12
  frameworkStatus:
    - name: soc2
      compliant: false
      score: 87.5
      violations: 12
```

---

## CLI Experience

### Design Philosophy

In v1, the CLI **is** the product. Every interaction — from installation to scan output to report generation — must feel polished, intentional, and impressive. DevOps engineers are opinionated about their tools and share exceptional CLI experiences. Beautiful terminal output is free marketing.

**Principles**:
1. **First impressions matter**: Post-install deployment validation creates an immediate "aha moment"
2. **Dual-mode output**: Every command supports both human-readable (styled, interactive) and machine-readable (`--output json`) modes. Pretty mode impresses humans; JSON mode makes the tool composable in CI/CD pipelines
3. **Progressive disclosure**: Show the essential information first, allow drill-down into details
4. **Adaptive styling**: Automatically detect light/dark terminal themes and adjust colors accordingly (Lipgloss handles this)
5. **Scriptability first**: Despite the visual polish, never break pipe-ability. Detect when stdout is not a TTY and fall back to plain text automatically

### Deployment Validation ("Aha Moment")

On first install via Helm, the operator runs an initial scan and outputs a styled summary to the pod logs. When a user runs `kubectl logs` or `varax status`, they immediately see:

```
┌──────────────────────────────────────────────────────┐
│  Varax v1.0.0                                   │
│  Cluster: production-eks-us-east-1                   │
│  Scan completed: 2026-06-15T10:23:45Z                │
├──────────────────────────────────────────────────────┤
│                                                      │
│  SOC2 Readiness Score:  ████████████░░░░  62/100     │
│                                                      │
│  ✓ 5 controls passing    ✗ 3 critical findings       │
│  ◐ 1 partial                                         │
│                                                      │
│  Critical:                                           │
│  ├── CC6.1  2 ClusterRoleBindings with cluster-admin │
│  ├── CC6.6  6 namespaces missing NetworkPolicies     │
│  └── CC7.1  Audit logging not enabled                │
│                                                      │
│  Run 'varax scan' for full details              │
│  Run 'varax report --format html' (Pro)         │
└──────────────────────────────────────────────────────┘
```

This output uses Lipgloss for the bordered box, colored status badges (green ✓, red ✗, yellow ◐), and the score gauge. It renders in <1 second and gives immediate value before the user has done anything beyond `helm install`.

### CLI Commands

```bash
# Run as operator (default — starts controller loop)
varax operator

# One-shot scan with styled output
varax scan                            # Interactive: Bubble Tea spinner + styled results
varax scan --output json              # Machine-readable JSON (for CI/CD pipelines)
varax scan --output table             # Styled table (default for TTY)
varax scan --output plain             # No colors/borders (for piping/logging)
varax scan --watch                    # Bubble Tea live-updating scan view
varax scan --kubeconfig ~/.kube/config # Explicit kubeconfig

# Quick compliance status (lightweight, no full scan)
varax status                          # Styled summary box with score + top findings

# Generate compliance report (Pro)
varax report --framework soc2 --format html --output soc2-report.html
varax report --framework soc2 --format pdf --output soc2-report.pdf
varax report --framework soc2 --format terminal   # Rich terminal report via Glamour
varax report --framework soc2 --type executive --format pdf
varax report --framework soc2 --type readiness --format html

# Generate evidence for specific control (Pro)
varax evidence --control CC6.1 --format html --output cc6.1-evidence.html
varax evidence --all --format pdf --output evidence-package.pdf

# Interactive control explorer (Pro)
varax explore                         # Bubble Tea TUI: navigate controls, drill into findings

# Check license status
varax license status
varax license activate <LICENSE_KEY>

# Shell completions (auto-generated by Cobra)
varax completion bash > /etc/bash_completion.d/varax
varax completion zsh > "${fpath[1]}/_varax"
varax completion fish > ~/.config/fish/completions/varax.fish

# Version
varax version
```

### Output Modes

Every command that produces output supports multiple modes:

| Flag | Mode | When to Use | Styling |
|------|------|-------------|---------|
| `--output table` | Styled table | Default for interactive TTY | Lipgloss colors, borders, badges |
| `--output json` | JSON | CI/CD pipelines, scripting, integration | No styling, structured data |
| `--output plain` | Plain text | Piping, logging, non-TTY environments | No colors, no borders |
| `--format terminal` | Rich terminal | `varax report` only — full report in terminal | Glamour markdown rendering |
| (auto-detect) | TTY detection | Automatic | If stdout is not a TTY, fall back to plain |

### Styled Output Components

Built with Lipgloss and Bubble Tea, reusable across all commands:

**Compliance Score Gauge**: Colored progress bar with numeric score. Red (0–40), yellow (41–70), green (71–100). Renders inline in scan results and status views.

**Control Status Badges**: Inline colored labels — `PASS` (green), `FAIL` (red), `PARTIAL` (yellow), `NOT ASSESSED` (gray). Consistent across all commands.

**Summary Box**: Bordered container with scan metadata, score, and top findings. Used in `varax status` and post-scan output.

**Scan Progress**: Bubble Tea animated spinner with real-time check names. Shows which checks are running, how many have completed, and estimated time remaining. Used during `varax scan` in interactive mode.

**Control Table**: Styled table with control ID, description, status badge, and finding count. Proper column alignment, alternating row highlighting. Used in `varax scan --output table`.

**Interactive Explorer** (Pro): Bubble Tea full-screen TUI for `varax explore`. Navigate controls with arrow keys, press Enter to drill into findings, view evidence, and see remediation steps. Vim-style keybindings (`j`/`k` navigation, `q` to quit).

### Free vs Pro Feature Gating

| Feature | Free (OSS) | Pro ($149/mo or $1,490/yr) |
|---------|-----------|----------------------------|
| Compliance scanning (all checks) | ✅ | ✅ |
| Prometheus metrics | ✅ | ✅ |
| Auto-enable audit logging | ✅ | ✅ |
| `varax scan` (one-shot) | ✅ | ✅ |
| Basic CLI report (summary only, text/table) | ✅ | ✅ |
| Full SOC2 readiness report (HTML/PDF) | ❌ | ✅ |
| Per-control evidence pages | ❌ | ✅ |
| Executive summary report | ❌ | ✅ |
| Evidence package export | ❌ | ✅ |
| Historical trend data in reports | ❌ | ✅ |
| Auto-remediation (dry-run + apply) | ❌ | ✅ |
| Scheduled report generation | ❌ | ✅ |
| Email support | ❌ | ✅ |
| Community support (GitHub Issues) | ✅ | ✅ |

### Licensing System

**Mechanism**: Ed25519-signed license keys validated entirely offline — no phone-home, no external dependency.

**How it works**:
1. Customer purchases Pro on varax.io (Stripe Checkout)
2. Stripe webhook triggers key generation on a lightweight backend (single serverless function)
3. Backend generates an Ed25519-signed license key encoding: organization name, plan (monthly/annual), expiry date, and feature flags
4. Customer receives key via email and applies it:
   ```bash
   kubectl create secret generic varax-license \
     --from-literal=license-key="VARAX-PRO-xxxxxxxxxxxx" \
     -n varax-system
   ```
5. Operator validates the signature and expiry on startup and on each report generation
6. If the key is expired or missing, Pro features gracefully degrade to free tier (scanning continues, reports show upgrade prompt)

**Key format** (base64-encoded JSON + Ed25519 signature):
```json
{
  "org": "Acme Corp",
  "plan": "pro-annual",
  "issued": "2026-06-01T00:00:00Z",
  "expires": "2027-06-01T00:00:00Z",
  "features": ["reports", "evidence", "remediation", "scheduled-reports"]
}
```

**Renewal flow**:
- **Monthly subscribers**: Stripe charges monthly. On each successful charge, a new key valid for 35 days (5-day grace) is emailed automatically. Customer applies the new key.
- **Annual subscribers**: Stripe charges annually. Key is valid for 370 days (5-day grace). One renewal per year.
- **Grace period**: The operator continues working for 5 days past expiry to avoid disruption from missed renewal emails or delayed key rotation. After grace period, Pro features degrade to free.
- **Future improvement (v1.1)**: Add `varax license refresh` CLI command that hits a single API endpoint to fetch the latest key for active subscriptions — still optional, not required.

**Anti-piracy stance**: Minimal. At this price point and market (DevOps teams at funded startups), key sharing is not a meaningful concern. The license is per-organization, not per-cluster — a single key works across all of a customer's clusters. This is intentionally generous and reduces friction.

The free tier is fully functional for scanning and metrics — reports are the primary monetization lever.

### Report Types

#### 1. SOC2 Readiness Report (Primary Deliverable)

**Output**: 15–30 page HTML/PDF document

**Structure**:
- **Cover page**: Organization name, cluster name, report date, Varax version
- **Executive summary**: Overall compliance score, critical findings count, recommendation
- **Compliance score breakdown**: Visual gauge (0–100) with color coding
- **Control-by-control analysis**: For each SOC2 control:
  - Control ID and description
  - Status: PASS / FAIL / PARTIAL / NOT ASSESSED
  - Evidence collected (RBAC snapshots, encryption checks, etc.)
  - Specific findings (which resources failed)
  - Remediation steps for each failure
- **Trend analysis** (Pro): Score over time from stored scan history
- **Appendix**: Full list of CIS checks performed with pass/fail, cluster metadata

#### 2. Executive Summary Report

**Output**: 2–3 page PDF
- Compliance score with traffic light indicator
- Critical and high violations summary
- Top 5 remediation priorities
- Comparison to previous scan (if available)

#### 3. Evidence Package

**Output**: Multi-page HTML/PDF per control
- RBAC configuration snapshot (roles, bindings, service accounts)
- NetworkPolicy inventory
- Encryption status (at rest, in transit)
- Audit logging status and retention validation
- Pod Security Standard enforcement status
- Timestamped evidence suitable for auditor review

### Report Technology

Reports are delivered in four formats:

1. **HTML**: Go's `html/template` package with embedded CSS for professional styling. Self-contained single-file output with inline styles and base64-encoded assets. These are the reports featured as interactive samples on varax.io.

2. **PDF**: HTML → PDF conversion using one of:
   - **chromedp**: Headless Chrome (best quality, requires Chrome in container)
   - **go-wkhtmltopdf**: wkhtmltopdf wrapper (lighter weight, good enough for most cases)

3. **Terminal** (`--format terminal`): Rich terminal rendering via **Glamour** (charmbracelet/glamour) with custom stylesheets. Renders the full report as styled markdown directly in the terminal — headers, tables, colored badges, bordered sections. Useful for quick reviews without opening a browser or PDF viewer.

4. **JSON** (`--output json`): Machine-readable structured data for integration with other tools, CI/CD pipelines, or custom dashboards. Every data point in the HTML/PDF reports is available in JSON.

The report templates are embedded in the Go binary via `embed.FS` — no external file dependencies at runtime.

```go
//go:embed templates/*
var reportTemplates embed.FS

//go:embed assets/*
var reportAssets embed.FS
```

---

## Compliance Framework Mapping (SOC2)

### SOC2 Trust Services Criteria

| Control | Description | How Varax Validates | Evidence Generated |
|---------|-------------|------------------------|--------------------|
| **CC6.1** | Logical and physical access controls | Scans RBAC: cluster-admin bindings, overly permissive roles, service account privileges | RBAC snapshot: all Roles, ClusterRoles, Bindings with permission analysis |
| **CC6.2** | System credentials management | Detects shared service accounts, validates authentication configs, checks token auto-mounting | Service account inventory, token mount status, authentication config |
| **CC6.3** | Access removal | Identifies stale RBAC bindings, orphaned service accounts, unused roles | Stale binding list with last-used timestamps (from audit logs if available) |
| **CC6.6** | System boundaries protection | Validates NetworkPolicies exist, checks default-deny rules, scans ingress/egress | NetworkPolicy inventory, namespace coverage analysis, missing policy list |
| **CC6.8** | Vulnerability management | Scans for running images with known CVEs (via metadata), validates Pod Security Standards | PSS enforcement status per namespace, privileged container list |
| **CC7.1** | Detect unauthorized changes | Validates audit logging is enabled, checks log retention meets 13-month requirement | Audit log enablement proof, retention configuration, log flow validation |
| **CC7.2** | Monitor system components | Verifies operator is running, confirms Prometheus scraping, checks cluster health | Monitoring status, Prometheus endpoint validation, scan schedule confirmation |
| **CC7.3** | Evaluate security events | Aggregates scan violations by severity, provides remediation priority | Violation summary with severity distribution, remediation instructions |
| **CC8.1** | Restrict sensitive information | Scans for secrets in env vars, checks secret access patterns, validates encryption | Encryption-at-rest status, secret access patterns, env var scan results |

### HIPAA & PCI-DSS (v2 — Deferred)

The compliance mapping architecture is designed to be extensible. Each framework is implemented as a Go interface:

```go
type ComplianceFramework interface {
    Name() string
    Controls() []Control
    MapCheck(checkID string) []ControlMapping
    GenerateEvidence(control string, scanResults []ScanResult) Evidence
}
```

HIPAA (§164.312 Technical Safeguards) and PCI-DSS (Requirements 1, 2, 7, 8, 10, 11) mappings will be added in v2, using the same scanning infrastructure with framework-specific evidence templates.

---

## Prometheus Metrics

The operator exposes metrics at `:8080/metrics`:

```prometheus
# Compliance score (0-100) per framework
varax_compliance_score{framework="soc2", cluster="prod"} 87.5

# Violation counts by severity
varax_violations_total{severity="critical", framework="soc2"} 2
varax_violations_total{severity="high", framework="soc2"} 5
varax_violations_total{severity="medium", framework="soc2"} 3
varax_violations_total{severity="low", framework="soc2"} 2

# Individual control status (1=pass, 0=fail)
varax_control_status{framework="soc2", control="CC6.1"} 1
varax_control_status{framework="soc2", control="CC7.1"} 0

# Audit logging health
varax_audit_logging_enabled{provider="eks", cluster="prod"} 1
varax_audit_log_lag_seconds{cluster="prod"} 12

# Scan status
varax_last_scan_timestamp{cluster="prod"} 1709125200
varax_scan_duration_seconds{cluster="prod"} 45.2
varax_checks_total{status="pass"} 95
varax_checks_total{status="fail"} 15
varax_checks_total{status="warning"} 10

# Report generation (Pro)
varax_reports_generated_total{framework="soc2", type="readiness"} 3
varax_last_report_timestamp{cluster="prod"} 1709125200

# Remediation
varax_remediations_applied_total{action="addResourceLimits"} 15
varax_remediations_pending{cluster="prod"} 3
```

---

## Helm Chart

### values.yaml

```yaml
image:
  repository: ghcr.io/varax/operator
  tag: latest
  pullPolicy: IfNotPresent

replicaCount: 1

config:
  scanInterval: "1h"
  framework: soc2
  auditLogging:
    autoEnable: true
    retentionDays: 395
  remediation:
    enabled: false
    dryRun: true

# Pro license key (purchase at varax.io)
# Per-organization — one key works across all clusters
license:
  enabled: false                     # Set to true after purchasing Pro
  secretRef:
    name: varax-license
    key: license-key
  # Apply with:
  # kubectl create secret generic varax-license \
  #   --from-literal=license-key="VARAX-PRO-xxxx" \
  #   -n varax-system

# Cloud provider credentials (for audit log enablement)
cloudProvider:
  aws:
    enabled: false
    serviceAccount:
      annotations:
        eks.amazonaws.com/role-arn: ""
  azure:
    enabled: false
  gcp:
    enabled: false

# Persistent storage for scan history and evidence
persistence:
  enabled: true
  size: 1Gi
  storageClass: ""               # Use cluster default

# Prometheus ServiceMonitor
prometheus:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s

resources:
  limits:
    cpu: 200m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

serviceAccount:
  create: true
  name: varax-operator
```

### NOTES.txt

```
🛡️  Varax is now running!

Your cluster is being scanned for SOC2 compliance.

📊 Quick start:

1. Check compliance score:
   kubectl exec -n {{ .Release.Namespace }} deploy/varax -- varax scan --output table

2. Generate a report (Pro):
   kubectl exec -n {{ .Release.Namespace }} deploy/varax -- \
     varax report --framework soc2 --format html --output /tmp/report.html
   kubectl cp {{ .Release.Namespace }}/$(kubectl get pod -n {{ .Release.Namespace }} -l app=varax -o name | head -1 | sed 's/pod\///'):/tmp/report.html ./soc2-report.html

3. View metrics:
   kubectl port-forward -n {{ .Release.Namespace }} svc/varax 8080:8080
   curl http://localhost:8080/metrics | grep varax

📖 Documentation: https://github.com/varax/operator
🔑 Get a Pro license: https://varax.io/pricing
```

---

## RBAC & Security

### Operator RBAC (Minimal Permissions)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: varax-operator
rules:
  # Read cluster resources for scanning (read-only)
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps", "serviceaccounts", "namespaces"]
    verbs: ["get", "list", "watch"]

  # Read secrets metadata only (NEVER read .data)
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]

  - apiGroups: ["apps"]
    resources: ["deployments", "daemonsets", "statefulsets"]
    verbs: ["get", "list", "watch"]

  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["get", "list", "watch"]

  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch"]

  # Auto-remediation (opt-in, disabled by default)
  - apiGroups: [""]
    resources: ["pods", "services"]
    verbs: ["patch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["create"]

  # Operator's own CRDs
  - apiGroups: ["compliance.varax.io"]
    resources: ["*"]
    verbs: ["*"]
```

### Security Posture
- Read-only access by default (remediation opt-in)
- No secrets `.data` access — only metadata
- No cluster-admin, no kube-system modifications
- Runs as non-root, no privilege escalation
- Distroless base image
- Container images signed with Cosign/Sigstore
- SBOM generated for each release
- Dependency scanning via `govulncheck` in CI
- **No external network calls** (unless audit logging enablement needs cloud API access)

### Cloud Provider Permissions

Same as v2.0 PRD — IRSA (AWS), Workload Identity (GCP/Azure). No static credentials.

---

## v2 Architecture: SaaS Dashboard (Future)

**Built only after v1 proves product-market fit.** Criteria to start v2:
- 10+ paying Pro customers on v1
- $1,500+ MRR from CLI licenses
- Clear signal that customers want multi-cluster dashboard

### v2 Adds Two New Repositories

1. **varax-api** (FastAPI, PostgreSQL + TimescaleDB, Redis)
   - Multi-tenant API for compliance data aggregation
   - OAuth authentication (Google, GitHub)
   - Evidence storage and management
   - Report generation (server-side)

2. **varax-dashboard** (Next.js, React, TypeScript)
   - Compliance score dashboard
   - Violation list, control matrix, evidence library
   - Report wizard UI
   - Team collaboration, settings

### v2 Pricing
- **Pro CLI** ($149/month or $1,490/year): Everything in v1 (unchanged)
- **Pro SaaS** ($199/month or $1,990/year): CLI + SaaS dashboard, 1 cluster
- **Enterprise** ($999–$2,999/month): Multi-cluster, SSO, SLA, custom policies, HIPAA/PCI-DSS

### v2 Additional Frameworks
- HIPAA Technical Safeguards (§164.312)
- PCI-DSS Requirements (1, 2, 7, 8, 10, 11)

The compliance mapping infrastructure in v1 is designed for this extension — each framework implements the same `ComplianceFramework` interface.

---

## Pricing & Business Model

### v1 Pricing

#### Free Tier (Open Source)
- Varax operator (unlimited clusters, unlimited scans)
- Prometheus metrics export
- CIS Benchmark + NSA hardening scanning
- SOC2 control mapping (score + violation list)
- `varax scan` CLI output (text/table format)
- Basic summary report (text/table — not formatted HTML/PDF)
- Auto-enable audit logging
- Community support (GitHub Issues)

#### Pro Tier

| Plan | Price | Effective Monthly | Savings |
|------|-------|-------------------|---------|
| **Pro Monthly** | $149/month | $149/mo | — |
| **Pro Annual** | $1,490/year (upfront) | ~$124/mo | 2 months free (~$298 saved) |

**What Pro includes** (everything in Free, plus):
- Full SOC2 readiness report (HTML/PDF) — the audit-ready document
- Per-control evidence pages with RBAC snapshots, encryption validation, network policy inventory
- Executive summary report (2–3 page PDF for leadership)
- Evidence package export (all controls in one document)
- Historical trend data in reports (from stored scan history)
- Auto-remediation engine (dry-run + apply, opt-in)
- Scheduled report generation (e.g., monthly)
- Email support (48-hour response)

**License model**: Per-organization, not per-cluster. One license key works across all clusters in the customer's environment. This is intentionally generous — it reduces friction and matches how DevOps teams actually work.

**License delivery**: Customer purchases on varax.io via Stripe Checkout (supports both monthly and annual billing). Stripe webhook triggers automatic license key generation and email delivery. Customer applies key as a Kubernetes Secret. See [Licensing System](#licensing-system) for full technical details.

**Why $149/month**: It's below the threshold where most startups require procurement approval (typically $500+/month). A senior DevOps engineer earns ~$75/hour — Varax saves 40–100 hours per audit cycle. At $149/month ($1,788/year), the ROI is 13–42x. The annual discount at $1,490 makes it even more compelling and locks in revenue for 12 months.

**Annual subscription incentives**: Target 40–60% of customers on annual plans. Benefits for the business: reduced churn (12-month commitment), better cash flow (upfront payment), and simplified forecasting. Benefits for the customer: ~$298 savings per year and no monthly renewal hassle.

### Revenue Projections (v1 Only)

Assumes 40% of Pro subscribers choose annual plans by Month 12.

| Month | Free Users | Pro Monthly | Pro Annual | Consulting | MRR | Notes |
|-------|------------|-------------|------------|------------|-----|-------|
| 1–3 | 50 | 0 | 0 | $0 | $0 | Building |
| 4–5 | 150 | 2 | 0 | $2K one-time | $298 | Launch, first paying customers |
| 6–8 | 300 | 5 | 2 | $4K one-time | $993 | 5×$149 + 2×($1,490÷12) |
| 9–12 | 500 | 12 | 8 | $8K one-time | $2,781 | 12×$149 + 8×($1,490÷12) |

**Target**: $3,000 MRR by Month 10–12 from ~20 Pro subscribers (mix of monthly and annual) + consulting revenue on top.

**Cash flow note**: Each annual subscriber pays $1,490 upfront. With 8 annual subscribers by Month 12, that's $11,920 in upfront cash collected during the year — significantly better than monthly billing alone.

---

## Go-to-Market Strategy

### Phase 1: Open Source Launch (Months 1–3, during build)

**Channels** (start before v1 is complete):
1. **Content marketing**: Blog posts about K8s compliance, SOC2 for DevOps teams
2. **GitHub**: Operator repo with comprehensive README, demo reports in `/examples/`
3. **Reddit**: r/kubernetes, r/devops, r/sysadmin
4. **Hacker News**: "Show HN: Open-source K8s compliance scanning with SOC2 mapping"
5. **Kubernetes Slack**: #varax channel

**Early content ideas**:
- "The 10 CIS Benchmark Checks That Fail Every SOC2 Audit"
- "Auto-Enable Kubernetes Audit Logging in 60 Seconds"
- "SOC2 for Kubernetes: What Your Auditor Actually Needs"

**Goals**: 500+ GitHub stars, 1,000+ Docker Hub pulls, 100+ email subscribers

### Phase 2: Pro Launch (Months 4–6)

**Channels**:
1. Email all open-source users: "Generate audit-ready SOC2 reports from your cluster"
2. In-product: `varax report` on free tier shows "Upgrade to Pro for full report"
3. LinkedIn: Target DevOps Engineers, SREs, CTOs at Series A–C startups
4. Blog: Sample report walkthrough, "What my auditor said about Varax reports"

**Conversion funnel**:
- GitHub star → Email signup → Free install → Try `varax report` → See upgrade prompt → Buy Pro ($149/mo or $1,490/yr)
- Target: 5–8% conversion from free to Pro

### Phase 3: Expand & Validate v2 (Months 7–12)

**Focus**: Grow Pro subscriber base, test appetite for SaaS dashboard
1. Survey Pro customers: "Would you pay $199/month for a web dashboard?"
2. Consulting engagements (see below) to learn enterprise needs
3. Conference presence: KubeCon, DevOps Days (attend, not exhibit)
4. Partnerships: SOC2 audit firms (referral commission for recommending Varax)

---

## Consulting Hybrid Model

While the product matures, offer **paid Kubernetes compliance audit engagements** to generate revenue and learn what customers actually need.

### Service Offering

**"Varax SOC2 Readiness Assessment"** — $2,000–$5,000 per engagement

**What you deliver**:
1. Install Varax operator on client's cluster(s)
2. Run comprehensive scan + generate report
3. Manual review of RBAC, network policies, audit logging
4. Written recommendations with remediation priority
5. 1-hour walkthrough call with the client's team
6. Follow-up scan 30 days later to validate fixes

**Time investment**: ~10–15 hours per engagement

**Why this matters**:
- Generates immediate revenue (Month 4+) while product matures
- Teaches you exactly what customers need (better than any PRD)
- Creates case studies and testimonials for marketing
- Each client becomes a Pro subscriber after the engagement
- Builds relationships with audit firms (referral channel)

### Pricing Justification
- Manual SOC2 evidence collection costs $15K–$75K in engineer time
- Compliance consultants charge $200–$500/hour
- $2K–$5K for a tool-assisted assessment is extremely competitive

---

## Development Phases (v1)

### Phase 1: Operator Core (Weeks 1–4)

**Goal**: Operator that auto-enables audit logging and performs basic CIS scanning with polished CLI output

**Deliverables**:
1. Kubebuilder scaffolding with ComplianceConfig CRD
2. **Cobra CLI structure**: `varax operator`, `varax scan`, `varax version` commands with shell completion generation
3. **Lipgloss style foundation**: Define color palette, status badges (PASS/FAIL/PARTIAL), bordered summary box, adaptive light/dark theme
4. Cloud provider auto-detection (EKS/AKS/GKE/self-hosted)
5. Auto-enable audit logging via AWS SDK (EKS first)
6. Basic CIS Benchmark scanner (top 20 critical checks)
7. SOC2 control mapping for those 20 checks
8. **Deployment validation output**: Post-install "aha moment" with styled compliance score gauge and critical findings
9. Prometheus metrics endpoint
10. Helm chart for installation (with deployment validation in NOTES.txt)
11. Unit tests (>80% coverage)
12. BoltDB local storage for scan history
13. **Dual-mode output**: `--output table` (styled), `--output json` (machine-readable), auto-detect TTY

**Success criteria**: Operator installs via Helm in <2 minutes, auto-detects EKS, enables audit logging, runs CIS scan, and displays a beautifully styled compliance summary that DevOps engineers would screenshot and share.

### Phase 2: Full Scanner + Evidence (Weeks 5–8)

**Goal**: Complete scanning engine with evidence collection and interactive scan experience

**Deliverables**:
1. Complete CIS Benchmark scanner (120+ checks)
2. NSA/CISA hardening guide scanner
3. Pod Security Standards checker
4. RBAC analyzer (least privilege)
5. Full SOC2 control mapping for all checks
6. Compliance score calculation
7. Evidence collector (RBAC snapshots, network policies, encryption status, audit log validation)
8. `varax scan` CLI command (one-shot mode) with **Bubble Tea animated scan progress** — real-time spinner showing current check, completion count, and ETA
9. **Styled control table**: Full scan results rendered as aligned, colored table with status badges per control
10. Azure AKS + GCP GKE audit log enablement
11. `varax status` command — lightweight styled summary without triggering a full scan

**Success criteria**: Full scan completes in <60 seconds, all 9 SOC2 controls have mapped checks, evidence snapshots stored locally. Scan output looks professional with animated progress and styled results.

### Phase 3: Report Generator (Weeks 9–12)

**Goal**: Professional HTML/PDF/terminal reports from CLI with interactive explorer

**Deliverables**:
1. HTML report templates (readiness, executive, per-control evidence)
2. Go html/template rendering engine
3. PDF conversion (chromedp or wkhtmltopdf)
4. Embedded CSS for professional styling
5. `varax report` CLI command with all format options (html, pdf, terminal, json)
6. **Terminal report rendering**: `--format terminal` using Glamour for styled markdown output directly in the terminal
7. `varax evidence` CLI command
8. **Interactive explorer TUI** (Pro): `varax explore` — Bubble Tea full-screen interface to navigate controls, drill into findings, view evidence, and read remediation steps. Vim-style keybindings (j/k navigation, Enter to expand, q to quit)
9. Historical trend data in reports (from BoltDB scan history)
10. License key validation system
11. Free vs Pro feature gating

**Success criteria**: `varax report --format pdf` generates a professional 20-page SOC2 readiness report that an auditor would recognize as useful evidence. `varax report --format terminal` renders a beautiful rich report directly in the terminal. `varax explore` provides an interactive, navigable compliance dashboard in the terminal.

### Phase 4: Polish & Launch (Weeks 13–14)

**Goal**: Production-ready release with documentation and exceptional first impressions

**Deliverables**:
1. Auto-remediation engine (opt-in, dry-run default)
2. README with demo report screenshots, quick start guide, **terminal output GIFs showing scan progress and styled results**
3. Documentation site (installation, configuration, SOC2 mapping reference)
4. GitHub Actions CI/CD (build, test, release, Helm publish)
5. Container image published to GHCR (with Cosign signature)
6. Helm chart published to GitHub Pages
7. Sample reports in `/examples/` — both HTML files and **terminal output screenshots**
8. Landing page (varax.io) with Stripe integration and **interactive sample HTML reports** that prospects can click through (table of contents, expandable control sections, evidence previews)
9. Cross-promotion for k8s-cronjob-monitor community

**Success criteria**: Anyone can install, scan, and generate a report in under 5 minutes. The deployment validation output creates an immediate "aha moment". The website sample reports serve as the product demo. Pro purchase flow works end-to-end.

---

## Open Source Strategy

### License: Apache 2.0

**Why Apache 2.0**:
- Permissive license that allows commercial use
- Patent grant protection for users
- Enterprise-friendly (same license as Kubernetes, Prometheus)
- Encourages adoption without legal friction

### Open Core Model (v1)

| Component | License | Rationale |
|-----------|---------|-----------|
| Operator (scanning, metrics, audit logging) | Apache 2.0 (Open) | Trust, adoption, community |
| Basic CLI scan output | Apache 2.0 (Open) | Adoption driver |
| Full report templates | Proprietary (Pro) | Revenue |
| Evidence package export | Proprietary (Pro) | Revenue |
| Auto-remediation | Proprietary (Pro) | Revenue |
| Scheduled reports | Proprietary (Pro) | Revenue |

**The free tier is genuinely useful** — scanning, metrics, and basic output are valuable without paying. Reports are the natural upsell when users need to hand something to an auditor.

### Community Management
- GitHub Issues for bug reports and feature requests
- GitHub Discussions for questions and ideas
- Kubernetes Slack channel (#varax)
- Clear CONTRIBUTING.md with development setup instructions

---

## Risk Analysis

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Cloud provider API changes break audit enablement | Medium | High | Abstract provider interface, integration tests per provider |
| CIS Benchmark updates require scanner updates | High | Medium | Modular check architecture, automated test suite per benchmark version |
| HTML/PDF report quality insufficient for auditors | Medium | High | Test with real auditors early (consulting engagements), iterate on templates |
| BoltDB/local storage limitations at scale | Low | Medium | Design storage interface for easy swap to external DB in v2 |
| Kubescape releases similar report features | Medium | High | Ship fast, differentiate on report quality and auditor focus |

### Business Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Slow OSS-to-paid conversion | Medium | High | Free tier genuinely useful; report upsell is natural and visible |
| $149 too low for enterprise, too high for indie | Low | Medium | Annual discount at $1,490 sweetens the deal; enterprise tier deferred to v2 at $999+ |
| Consulting doesn't scale | Expected | Low | Consulting is a bridge to product revenue, not the business model |
| Customers want SaaS dashboard before v2 is ready | Medium | Medium | Use consulting to deliver dashboard-equivalent service manually |
| Not being SOC2 certified yourself | High (Year 1) | High | Use own product to prepare; budget $10K–$15K for Type 1 audit |

### Competitive Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| ARMO/Kubescape adds report generation | Medium | High | Ship first, build community moat, differentiate on auditor-readiness |
| ARMO's per-node pricing undercuts on small clusters | Medium | Medium | Our flat rate is more attractive for clusters with many small nodes |
| Large vendor (Datadog, Prisma) adds K8s compliance | Low | Medium | They'll price at $100K+; we're the affordable alternative |

---

## Success Metrics

### Technical Metrics
- Operator installation success rate >95%
- Full scan completion time <60 seconds
- Report generation time <30 seconds
- False positive rate <5%
- Zero external network calls (except cloud API for audit logging)
- **CLI experience**: Deployment validation displays styled compliance summary within 60 seconds of `helm install`. All styled output renders correctly across macOS Terminal, iTerm2, Windows Terminal, and common Linux terminal emulators. JSON output validates against published schema. TTY auto-detection seamlessly falls back to plain text in CI/CD pipelines.

### Community Metrics (Months 1–6)
- GitHub stars: 500+ by month 6
- Docker Hub / GHCR pulls: 5,000+ by month 6
- Active installations (telemetry, opt-in): 200+
- Community contributors: 10+

### Business Metrics (Months 6–12)
- Pro subscribers: 20+ by month 12
- Consulting engagements: 5+ by month 12
- MRR: $3,000+ by month 10–12
- Free-to-paid conversion: >5%
- Monthly churn: <5%

### Product-Market Fit Signals (Triggers for v2)
- 10+ Pro customers requesting multi-cluster support
- 3+ customers asking for web dashboard
- $1,500+ MRR sustained for 2+ months
- Audit firm referral producing inbound leads

---

## Relationship to k8s-cronjob-monitor

Varax is part of a two-product strategy:

### Product 1: k8s-cronjob-monitor (Build First — Weeks 1–3)
- **Purpose**: Free, open-source CronJob monitoring for Kubernetes
- **Strategic role**: Brand building, community growth, operator development practice
- **Revenue**: $0 (intentionally free forever)

### Product 2: Varax Compliance Platform (Build Second — Weeks 4–17)
- **Purpose**: Revenue-generating compliance automation
- **Strategic role**: Primary business
- **Revenue**: Target $3K+ MRR

### Cross-Promotion

**In k8s-cronjob-monitor README/docs:**
```
## 🔒 Need SOC2 Compliance for Kubernetes?

Check out Varax by the same team:
→ Scan your cluster for compliance violations
→ Auto-enable audit logging on EKS/AKS/GKE
→ Generate audit-ready SOC2 reports from the CLI
→ https://varax.io
```

**In Varax marketing:**
```
From the creators of k8s-cronjob-monitor
Trusted by 5,000+ Kubernetes users
```

### Timeline
1. **Weeks 1–3**: Build and launch k8s-cronjob-monitor
2. **Weeks 4–17**: Build Varax v1 (operator + CLI reports)
3. **Month 4–5**: Launch Varax Pro tier + first consulting engagements
4. **Month 6–8**: Grow Pro subscriber base, validate v2 demand
5. **Month 10–12**: Target $3K MRR; begin v2 if signals are strong

---

## Appendix

### Glossary
- **BoltDB**: Embedded key-value store for Go (no external server needed)
- **CIS Benchmark**: Center for Internet Security Kubernetes security standard
- **CRD**: Custom Resource Definition — extends Kubernetes API
- **IRSA**: IAM Roles for Service Accounts (AWS)
- **MRR**: Monthly Recurring Revenue
- **NSA/CISA**: National Security Agency / Cybersecurity and Infrastructure Security Agency
- **OPA**: Open Policy Agent — policy engine
- **PCI-DSS**: Payment Card Industry Data Security Standard (v2)
- **PSS/PSA**: Pod Security Standards / Pod Security Admission
- **SOC2**: System and Organization Controls 2 (AICPA audit standard)

### References
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA Kubernetes Hardening Guide v1.2](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [SOC2 Trust Services Criteria](https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustservicescriteria)
- [Kubebuilder Documentation](https://book.kubebuilder.io/)
- [OPA Documentation](https://www.openpolicyagent.org/docs/)
- [Kubescape (primary competitor)](https://github.com/kubescape/kubescape)
- [ARMO Platform (commercial competitor)](https://www.armosec.io/)

### v2.0 PRD Reference
The full three-repository SaaS architecture is documented in Varax Compliance PRD v2.0. That document remains the reference for v2 implementation when the time comes. Key sections preserved for v2:
- Repository 2: varax-api (FastAPI, PostgreSQL + TimescaleDB)
- Repository 3: varax-dashboard (Next.js, React)
- Database schema (organizations, users, clusters, compliance_events, evidence, reports)
- API endpoints
- SaaS security (OAuth, JWT, RLS, encryption)
- HIPAA Technical Safeguards mapping (§164.312)
- PCI-DSS Requirements mapping (1, 2, 7, 8, 10, 11)

---

*Document Version: 3.0*
*Last Updated: February 2026*
*Status: Active Development*
*Build Approach: Claude Code assisted development*
