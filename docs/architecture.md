# Architecture

## System Overview

Varax is a single Go binary that serves two roles:

1. **CLI tool** — `varax scan` and `varax status` for one-shot compliance checks
2. **Kubernetes operator** — `varax operator` for continuous compliance monitoring via controller-runtime

Both modes share the same scanning engine, compliance mapper, and output layer.

```
                    ┌─────────────────────────────────────┐
                    │           varax binary          │
                    ├──────────────┬──────────────────────┤
                    │  CLI Mode    │   Operator Mode      │
                    │  (one-shot)  │   (continuous)       │
                    ├──────────────┴──────────────────────┤
                    │         Scanning Engine              │
                    │  ┌──────────────────────────────┐   │
                    │  │ Registry → Runner → Results   │   │
                    │  │  20 CIS Benchmark Checks      │   │
                    │  └──────────────────────────────┘   │
                    ├─────────────────────────────────────┤
                    │       Compliance Mapper              │
                    │  CIS Results → SOC2 Controls        │
                    │  Score = passing / assessed * 100   │
                    ├─────────────────────────────────────┤
                    │       Output Layer                   │
                    │  ┌─────────┬────────┬────────────┐  │
                    │  │ Styled  │ Plain  │ JSON       │  │
                    │  │(Lipgloss│(no ANSI│(machine    │  │
                    │  │  TTY)   │  pipe) │ readable)  │  │
                    │  └─────────┴────────┴────────────┘  │
                    ├─────────────────────────────────────┤
                    │     Storage        Metrics          │
                    │  (BoltDB local)  (Prometheus)       │
                    └─────────────────────────────────────┘
```

## Package Responsibilities

### `cmd/varax/`

CLI entry point. Defines the Cobra command tree and wires together all other packages.

- `main.go` — Root command, global flags (`--kubeconfig`, `--output`), kubeconfig resolution, BoltDB path
- `scan.go` — One-shot scan: build client, register checks, run, map, store, render
- `status.go` — Read latest stored scan from BoltDB, map, render
- `operator.go` — Start controller-runtime manager with ComplianceConfigReconciler
- `version.go` — Print version info (injected via ldflags at build time)

### `api/v1alpha1/`

Kubernetes CRD type definitions for `ComplianceConfig`. Contains:

- `complianceconfig_types.go` — Spec (framework, scanning, auditLogging, remediation, reports, alerts) and Status (phase, score, violations, conditions)
- `groupversion_info.go` — API group registration (`compliance.varax.io/v1alpha1`)
- `zz_generated.deepcopy.go` — Generated deep copy functions (regenerate with `make generate`)

### `internal/controller/`

The Kubernetes reconciliation loop. `ComplianceConfigReconciler.Reconcile()`:

1. Reads the `ComplianceConfig` CR
2. Sets status phase to `Scanning`
3. Optionally enables audit logging (if `spec.auditLogging.enabled`)
4. Runs all registered CIS checks
5. Maps results to SOC2 controls
6. Updates CRD status (score, violations, phase, framework status)
7. Records Prometheus metrics
8. Requeues after the configured interval

Also contains `reconcileAuditLogging()` which detects the cloud provider and delegates to the appropriate `AuditLogProvider` implementation.

### `pkg/scanning/`

The scanning engine core:

- **`scanner.go`** — `Check` interface (ID, Name, Description, Severity, Benchmark, Section, Run) and `Registry` (register, list, filter by benchmark)
- **`runner.go`** — `ScanRunner.RunAll()` executes all checks with panic recovery, context cancellation, and progress callbacks. Returns `ScanResult` with summary counts.

### `pkg/scanning/checks/`

20 CIS Benchmark check implementations, each in its own file. Every check:

- Implements the `scanning.Check` interface
- Uses the Kubernetes fake client in tests
- Skips system namespaces (`kube-system`, `kube-public`, `kube-node-lease`)
- Returns `StatusSkip` on API errors (non-fatal)
- Produces structured `Evidence` with resource reference, field name, and value

`registry.go` contains `RegisterAll()` which registers all 20 checks into a `Registry`.

### `pkg/compliance/`

SOC2 framework mapping and scoring:

- **`soc2_controls.go`** — Defines 9 SOC2 Trust Services Criteria controls and their CIS check mappings
- **`mapper.go`** — `SOC2Mapper.MapResults()` takes scan results, indexes by check ID, derives per-control status (PASS/FAIL/PARTIAL/NOT_ASSESSED), counts violations
- **`scorer.go`** — `Scorer.Calculate()` computes `(passing / assessed) * 100`, ignoring NOT_ASSESSED controls

### `pkg/providers/`

Cloud provider detection and audit log management:

- **`provider.go`** — `ProviderType` enum (EKS, AKS, GKE, SelfHosted) and `AuditLogProvider` interface
- **`detect.go`** — `DetectProvider()` reads node labels to determine the cloud provider
- **`aws/eks.go`** — EKS implementation using AWS SDK v2 (`DescribeCluster`, `UpdateClusterConfig`). Testable via `EKSClient` interface.
- **`selfhosted/audit_policy.go`** — Creates a ConfigMap in `kube-system` with a CIS-recommended audit policy YAML

### `pkg/cli/`

Terminal rendering layer:

- **`styles.go`** — Color palette, status badges (PASS/FAIL/PARTIAL/N/A) using Lipgloss
- **`theme.go`** — `OutputFormat` type, `IsTTY()` detection, `ResolveFormat()` logic
- **`score_gauge.go`** — `ScoreGauge()` (colored block progress bar) and `ScoreGaugePlain()` (ASCII)
- **`summary_box.go`** — `SummaryBox()` (bordered, colored) and `SummaryBoxPlain()` with framework, score, duration, control counts, critical findings
- **`control_table.go`** — `ControlTable()` (styled) and `ControlTablePlain()` with per-control ID, name, status badge, violation count
- **`json_output.go`** — `RenderJSON()` marshals to indented JSON on stdout

### `pkg/metrics/`

Prometheus metric declarations using `promauto`:

- `varax_compliance_score` (gauge vec: framework, cluster)
- `varax_violations_total` (gauge vec: severity, framework)
- `varax_control_status` (gauge vec: framework, control) with numeric mapping
- `varax_last_scan_timestamp` (gauge)
- `varax_scan_duration_seconds` (gauge)
- `varax_checks_total` (gauge vec: status)
- `varax_audit_logging_enabled` (gauge vec: provider, cluster)

### `pkg/storage/`

Local persistence for scan history:

- **`store.go`** — `Store` interface with `SaveScanResult`, `GetLatestScanResult`, `ListScanResults`, `Close`
- **`boltdb.go`** — BoltDB implementation. Scan results stored as JSON in a `scan_results` bucket, keyed by timestamp for natural ordering.

### `pkg/models/`

Shared data types used across packages:

- **`types.go`** — `Severity`, `CheckStatus`, `Resource`, `Evidence`, `CheckResult`, `ScanSummary`, `ScanResult`
- **`compliance.go`** — `ControlStatus`, `Control`, `ControlMapping`, `ControlResult`, `ComplianceResult`

## Data Flow

### CLI Scan

```
User runs: varax scan
    │
    ▼
buildK8sClient() ──── kubeconfig resolution
    │
    ▼
RegisterAll(registry) ──── 20 CIS checks registered
    │
    ▼
ScanRunner.RunAll() ──── Execute each check against K8s API
    │                     Panic recovery per check
    │                     Progress callback (styled mode)
    ▼
SOC2Mapper.MapResults() ── Index checks → map to controls → derive status → score
    │
    ├──▶ BoltStore.SaveScanResult() ──── Persist to ~/.varax/varax.db
    │
    └──▶ Render output (SummaryBox + ControlTable / JSON)
```

### Operator Reconciliation

```
ComplianceConfig CR created/updated
    │
    ▼
Reconcile() triggered
    │
    ├──▶ Set status.phase = Scanning
    │
    ├──▶ reconcileAuditLogging() ──── If auditLogging.enabled:
    │       │                          DetectProvider → EKS/SelfHosted/etc
    │       │                          IsAuditLoggingEnabled? → EnableAuditLogging
    │       ▼
    │    Record varax_audit_logging_enabled metric
    │
    ├──▶ RegisterAll + RunAll ──── Same scanning engine as CLI
    │
    ├──▶ MapResults ──── SOC2 compliance mapping
    │
    ├──▶ Update CRD status (score, violations, phase, framework status)
    │
    ├──▶ recordMetrics() ──── Push to Prometheus
    │
    └──▶ RequeueAfter(interval) ──── Schedule next scan
```

## Security Model

- **Read-only by default**: The operator only reads cluster resources for scanning. No write access to workloads.
- **Minimal RBAC**: ClusterRole grants get/list/watch on pods, services, configmaps, secrets, namespaces, nodes, RBAC resources, network policies, and deployments. Write access only to its own CRD and the audit policy ConfigMap.
- **No secrets data access**: While the operator can list secrets (to check for env var usage patterns), it examines metadata and references only — never reads secret `.data`.
- **Non-root container**: Runs as UID 65532 with read-only filesystem, no privilege escalation, all capabilities dropped.
- **Distroless base**: Minimal attack surface container image.
- **No external calls**: The binary makes no outbound network calls except cloud provider API calls for audit log enablement (when explicitly enabled).
