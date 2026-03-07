# Varax

**Automated Kubernetes compliance for SOC2 — scan, evidence, report.**

Varax is a Kubernetes-native SOC2 compliance automation platform. It runs as a single Go binary — an operator that continuously scans clusters for security violations, auto-enables audit logging, and maps findings to SOC2 Trust Services Criteria controls.

## Features

- **109 checks across 4 benchmarks** — 85 CIS Kubernetes Benchmark, 15 NSA/CISA Hardening Guide, 5 Pod Security Standards, 4 RBAC least-privilege checks
- **SOC2 control mapping** — every check maps to one or more of 16 SOC2 Trust Services Criteria controls (CC5.x, CC6.x, CC7.x, CC8.x, A1.x)
- **Shared responsibility model** — provider-managed checks (API server, etcd, control plane) are clearly distinguished from customer-controlled checks, with a dedicated section in reports for auditors
- **HTML reports** — readiness assessments and executive summaries with compliance scores, trend charts, and remediation guidance
- **Evidence collection** — auditor-ready evidence packages: RBAC snapshots, network policy coverage, audit log configuration, encryption status
- **Auto-enable audit logging** — detects EKS/AKS/GKE/self-hosted and enables control plane audit logs programmatically
- **Compliance scoring** — real-time 0-100 score based on passing vs. failing controls
- **Beautiful CLI output** — styled terminal output with score gauge, control table, and status badges (or plain text / JSON)
- **Free and Pro tiers** — scan and status are always free; reports, evidence export, and explore require a Pro license
- **Prometheus metrics** — `varax_compliance_score`, `varax_violations_total`, per-control status, scan duration
- **Kubernetes operator** — continuous reconciliation loop with configurable scan intervals via CRD
- **Local storage** — BoltDB-backed scan history for trend tracking
- **Helm chart** — install in under 2 minutes

See [examples/](examples/) for sample reports generated from synthetic data.

## Quick Start

### Prerequisites

- Go 1.25+
- A Kubernetes cluster (or kubeconfig pointing to one)
- `kubectl` configured

### Build from source

```bash
make build
```

### Run a one-shot scan

```bash
# Styled terminal output (auto-detected)
./bin/varax scan

# Plain text output
./bin/varax scan --output plain

# JSON output (machine-readable)
./bin/varax scan --output json
```

### View latest stored results

```bash
./bin/varax status
```

### Generate a compliance report (Pro)

```bash
# HTML readiness report
./bin/varax report --type readiness --format html -o report.html

# Executive summary
./bin/varax report --type executive --format html -o executive.html

# Export evidence for a specific control
./bin/varax evidence --control CC6.1 --format html -o evidence-CC6.1.html
```

### Install as operator (Helm)

```bash
helm install varax oci://ghcr.io/varaxlabs/charts/varax \
  --namespace varax-system \
  --create-namespace
```

Or install from source:

```bash
helm install varax ./helm/varax \
  --namespace varax-system \
  --create-namespace
```

See [Helm chart documentation](helm/varax/README.md) for all configuration options.

## Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| Compliance scanning (109 checks) | Yes | Yes |
| SOC2 control mapping and scoring | Yes | Yes |
| CLI output (styled/plain/JSON) | Yes | Yes |
| Prometheus metrics | Yes | Yes |
| Operator mode (continuous scanning) | Yes | Yes |
| Scan history and trends | Yes | Yes |
| HTML readiness reports | - | Yes |
| HTML executive summaries | - | Yes |
| Evidence export (per-control) | - | Yes |
| Shared responsibility section | - | Yes |

Activate a Pro license:

```bash
./bin/varax license activate <key>
./bin/varax license status
```

## CLI Reference

### Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--kubeconfig` | | Path to kubeconfig file (default: auto-detect) |
| `--output` | `-o` | Output format: `styled`, `plain`, `json` (default: auto-detect TTY) |

### Commands

#### `varax scan`

Run a one-shot compliance scan against the connected cluster. Registers all 109 checks across CIS, NSA/CISA, PSS, and RBAC benchmarks, executes them, maps results to SOC2 controls, computes a compliance score, and saves results to local BoltDB storage.

```bash
varax scan
varax scan -o json
varax scan --kubeconfig /path/to/config -o plain
```

#### `varax status`

Display the most recent stored scan results without running a new scan. Reads from BoltDB at `~/.varax/varax.db`.

```bash
varax status
varax status -o json
```

#### `varax report` (Pro)

Generate an HTML or JSON compliance report from the latest scan results.

```bash
varax report --type readiness --format html -o report.html
varax report --type executive --format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | `readiness` | Report type: `readiness`, `executive` |
| `--format` | `html` | Output format: `html`, `json` |
| `-o` | stdout | Output file path |

#### `varax evidence` (Pro)

Export auditor-ready evidence for SOC2 controls.

```bash
varax evidence --control CC6.1 --format html -o evidence.html
varax evidence --all --format json -o evidence.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--control` | | Specific SOC2 control ID (e.g., CC6.1) |
| `--all` | `false` | Export evidence for all controls |
| `--format` | `html` | Output format: `html`, `json` |

#### `varax license`

Manage Pro license activation.

```bash
varax license status
varax license activate <key>
```

#### `varax operator`

Start the controller-runtime operator for continuous scanning. Watches `ComplianceConfig` custom resources and reconciles on the configured interval.

```bash
varax operator
varax operator --metrics-bind-address :9090 --health-probe-bind-address :9091
```

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-bind-address` | `:8080` | Prometheus metrics endpoint |
| `--health-probe-bind-address` | `:8081` | Health/readiness probe endpoint |

#### `varax prune`

Remove old scan results from local storage.

```bash
varax prune --older-than 30d
```

#### `varax version`

Print version, git commit, and build timestamp.

```bash
varax version
```

## Benchmark Coverage

Varax implements 109 checks across 4 security benchmarks:

| Benchmark | Checks | Scope |
|-----------|--------|-------|
| CIS Kubernetes Benchmark v1.8 | 85 | RBAC, pod security, network policies, secrets, workload hardening, API server, etcd, control plane |
| NSA/CISA Kubernetes Hardening Guide | 15 | Network security, pod security, authentication, logging, supply chain |
| Pod Security Standards (PSS) | 5 | Baseline and Restricted enforcement at namespace level |
| RBAC Least Privilege | 4 | Cluster-admin audit, privilege escalation, overly permissive bindings |

### Shared Responsibility on Managed Kubernetes

On managed clusters (EKS, AKS, GKE), Varax automatically detects provider-managed components and reports them separately:

| CIS Section | Component | Managed K8s Status | Varax Action |
|-------------|-----------|-------------------|--------------|
| 1.2.x | API Server | Provider-managed | Reported as "Provider-Managed" |
| 1.3.x | Controller Manager | Provider-managed | Reported as "Provider-Managed" |
| 2.x | etcd | Provider-managed | Reported as "Provider-Managed" |
| 3.x | Audit Policy | Provider-managed | Reported as "Provider-Managed" |
| 4.2.x | Kubelet | Partially managed | Scans accessible settings |
| 5.x | Workload Security | Customer-controlled | Full scanning + evidence |

Reports include a dedicated **Shared Responsibility** section that maps provider-managed controls for auditors — showing exactly where the cloud provider's SOC2 report covers vs. what the customer needs to demonstrate.

All checks skip system namespaces (`kube-system`, `kube-public`, `kube-node-lease`).

## SOC2 Control Mapping

Each check maps to one or more SOC2 Trust Services Criteria controls:

| SOC2 Control | Name | Mapped Checks |
|-------------|------|---------------|
| CC5.1 | Control Activities Over Technology | CIS 1.2.x, 1.3.x, 4.2.x, PSS-1.x |
| CC5.2 | Policy and Procedure Controls | CIS 3.2, 1.2.16-17, PSS-2.x |
| CC6.1 | Logical and Physical Access Controls | CIS 5.1.x, 1.2.x, 2.x, NSA-AA, RBAC |
| CC6.2 | User Access Provisioning | CIS 5.1.5-7, NSA-AA |
| CC6.3 | Role-Based Access and Least Privilege | CIS 5.1.x, RBAC-1 through RBAC-4 |
| CC6.6 | Security Against Threats Outside System Boundaries | CIS 5.3.x, 5.2.5-8, NSA-NS |
| CC6.7 | Data Transmission and Movement Controls | CIS 1.2.23-26, 2.x |
| CC6.8 | Controls Against Malicious Software | CIS 5.2.x, 4.2.x, NSA-PS, NSA-SC, PSS |
| CC7.1 | Detect and Monitor Anomalies | CIS 5.x, 1.2.x, 3.2, NSA-LM |
| CC7.2 | Monitor System Components | CIS 5.2.3, 5.3.2, 4.2.9 |
| CC7.3 | Evaluate Security Events | CIS 5.2.3, 5.3.2, 3.2 |
| CC7.4 | Respond to Security Incidents | CIS 1.2.9, 1.2.20 |
| CC7.5 | Recover from Security Incidents | CIS 1.2.18-19 |
| CC8.1 | Change Management | CIS 5.1.2, 5.4.1, NSA-VM, PSS |
| A1.1 | Availability Capacity Planning | CIS 5.7.1, NSA-PS-8 |
| A1.2 | Availability Environmental Protections | CIS 1.3.1, 4.2.5-7 |

### Scoring

The compliance score is calculated as:

```
score = (passing_controls / assessed_controls) * 100
```

Controls with no mapped check results are marked `NOT_ASSESSED` and excluded from the score calculation. Controls where all checks pass are `PASS`, all fail are `FAIL`, and mixed results are `PARTIAL`.

## Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `varax_compliance_score` | Gauge | framework, cluster | Overall compliance score (0-100) |
| `varax_violations_total` | Gauge | severity, framework | Violation count by severity |
| `varax_control_status` | Gauge | framework, control | Per-control status (1=pass, 0.5=partial, 0=fail, -1=n/a) |
| `varax_last_scan_timestamp` | Gauge | | Unix timestamp of last scan |
| `varax_scan_duration_seconds` | Gauge | | Duration of last scan |
| `varax_checks_total` | Gauge | status | Check count by status (pass/fail/warn/skip) |
| `varax_audit_logging_enabled` | Gauge | provider, cluster | Whether audit logging is enabled (1/0) |

## Cloud Provider Support

### Audit Log Auto-Enablement

| Provider | Detection | Action | Status |
|----------|-----------|--------|--------|
| **EKS** | `eks.amazonaws.com/*` node labels | `UpdateClusterConfig` via AWS SDK -- enables all 5 log types | Implemented |
| **AKS** | `kubernetes.azure.com/*` node labels | Diagnostic settings via Azure SDK | Phase 2 |
| **GKE** | `cloud.google.com/*` node labels | Verify/enable Data Access logs via GCP SDK | Phase 2 |
| **Self-hosted** | Fallback | Creates ConfigMap with CIS-recommended audit policy in `kube-system` | Implemented |

EKS audit logging requires IAM permissions. Use IRSA (IAM Roles for Service Accounts):

```yaml
# helm/varax values override
cloudProvider:
  aws:
    enabled: true
    serviceAccount:
      annotations:
        eks.amazonaws.com/role-arn: "arn:aws:iam::ACCOUNT:role/varax"
```

## ComplianceConfig CRD

The operator is configured via the `ComplianceConfig` custom resource:

```yaml
apiVersion: compliance.varax.io/v1alpha1
kind: ComplianceConfig
metadata:
  name: soc2-compliance
  namespace: varax-system
spec:
  framework: SOC2
  scanning:
    interval: "5m"
    excludeNamespaces:
      - kube-system
      - kube-public
      - kube-node-lease
  auditLogging:
    enabled: false
  remediation:
    autoRemediate: false
    dryRun: true
```

Status is reported via the subresource:

```bash
kubectl get complianceconfigs -n varax-system
# NAME              FRAMEWORK   SCORE   VIOLATIONS   PHASE        AGE
# soc2-compliance   SOC2        78      5            Violations   10m
```

## Development

```bash
# Build
make build

# Run tests with race detector and coverage
make test

# Format code
make fmt

# Run linter
make lint

# Generate deep copy functions
make generate

# Build Docker image
make docker-build

# Regenerate sample reports
make examples

# Clean build artifacts
make clean
```

## Architecture

```
cmd/varax/               CLI entry points (scan, status, report, evidence, license, operator, version)
api/v1alpha1/            CRD type definitions (ComplianceConfig)
internal/controller/     Kubernetes controller reconciliation loop
pkg/scanning/            Check interface, registry, and scan runner
pkg/scanning/checks/     109 benchmark check implementations (CIS, NSA, PSS, RBAC)
pkg/compliance/          SOC2 control definitions, mapper, and scorer
pkg/reports/             HTML report generator, templates, remediation guidance
pkg/evidence/            Evidence collection (RBAC, network, audit, encryption)
pkg/license/             Ed25519 license validation and Pro feature gating
pkg/rbac/                RBAC analyzer for least-privilege checks
pkg/providers/           Cloud provider detection and audit log enablement
pkg/cli/                 Terminal UI components (Lipgloss styles, score gauge, tables)
pkg/metrics/             Prometheus metric definitions
pkg/storage/             BoltDB scan result persistence
pkg/models/              Shared data types
helm/varax/              Helm chart for Kubernetes deployment
examples/                Sample HTML reports (generated from synthetic data)
```

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.
