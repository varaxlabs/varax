# Varax

**Automated Kubernetes compliance for SOC2 — scan, evidence, report.**

Varax is a Kubernetes-native SOC2 compliance automation platform. It runs as a single Go binary — an operator that continuously scans clusters for security violations, auto-enables audit logging, and maps findings to SOC2 Trust Services Criteria controls.

## Features

- **20 CIS Benchmark checks** covering RBAC, pod security, network policies, secrets, and workload hardening
- **SOC2 control mapping** — every check maps to one or more SOC2 Trust Services Criteria controls (CC6.x, CC7.x, CC8.x)
- **Auto-enable audit logging** — detects EKS/AKS/GKE/self-hosted and enables control plane audit logs programmatically
- **Compliance scoring** — real-time 0–100 score based on passing vs. failing controls
- **Beautiful CLI output** — styled terminal output with score gauge, control table, and status badges (or plain text / JSON)
- **Prometheus metrics** — `varax_compliance_score`, `varax_violations_total`, per-control status, scan duration
- **Kubernetes operator** — continuous reconciliation loop with configurable scan intervals via CRD
- **Local storage** — BoltDB-backed scan history for trend tracking
- **Helm chart** — install in under 2 minutes

## Quick Start

### Prerequisites

- Go 1.23+
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

### Install as operator (Helm)

```bash
helm install varax ./helm/varax \
  --namespace varax-system \
  --create-namespace
```

See [Helm chart documentation](helm/varax/README.md) for all configuration options.

## CLI Reference

### Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--kubeconfig` | | Path to kubeconfig file (default: auto-detect) |
| `--output` | `-o` | Output format: `styled`, `plain`, `json` (default: auto-detect TTY) |

### Commands

#### `varax scan`

Run a one-shot compliance scan against the connected cluster. Registers all 20 CIS checks, executes them, maps results to SOC2 controls, computes a compliance score, and saves results to local BoltDB storage.

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

#### `varax version`

Print version, git commit, and build timestamp.

```bash
varax version
```

## CIS Benchmark Checks

Varax implements 20 checks from the CIS Kubernetes Benchmark v1.8, Section 5 (Policies):

### RBAC (CIS 5.1)

| ID | Check | Severity |
|----|-------|----------|
| CIS-5.1.1 | Restrict cluster-admin ClusterRoleBinding usage | CRITICAL |
| CIS-5.1.2 | Minimize access to secrets | HIGH |
| CIS-5.1.3 | Minimize wildcard use in Roles and ClusterRoles | HIGH |
| CIS-5.1.5 | Ensure default service accounts are not actively used | MEDIUM |
| CIS-5.1.6 | Ensure service account tokens are not auto-mounted | MEDIUM |
| CIS-5.1.8 | Limit use of bind, escalate, and impersonate permissions | HIGH |

### Pod Security (CIS 5.2)

| ID | Check | Severity |
|----|-------|----------|
| CIS-5.2.1 | Ensure allowPrivilegeEscalation is set to false | CRITICAL |
| CIS-5.2.2 | Ensure containers run as non-root | HIGH |
| CIS-5.2.3 | Minimize privileged containers | CRITICAL |
| CIS-5.2.4 | Ensure containers drop ALL capabilities | HIGH |
| CIS-5.2.5 | Ensure hostPID is not set | CRITICAL |
| CIS-5.2.6 | Ensure hostIPC is not set | HIGH |
| CIS-5.2.7 | Ensure hostNetwork is not set | HIGH |
| CIS-5.2.8 | Limit container hostPort usage | MEDIUM |
| CIS-5.2.13 | Minimize added capabilities | MEDIUM |

### Network Policies (CIS 5.3)

| ID | Check | Severity |
|----|-------|----------|
| CIS-5.3.2 | Ensure every namespace has a NetworkPolicy | HIGH |

### Secrets Management (CIS 5.4)

| ID | Check | Severity |
|----|-------|----------|
| CIS-5.4.1 | Prefer using Secrets as files over environment variables | MEDIUM |

### General Security (CIS 5.7)

| ID | Check | Severity |
|----|-------|----------|
| CIS-5.7.2 | Ensure Seccomp profile is set | MEDIUM |
| CIS-5.7.3 | Ensure security context is applied to pods and containers | HIGH |
| CIS-5.7.4 | Ensure default namespace is not used | MEDIUM |

All checks skip system namespaces (`kube-system`, `kube-public`, `kube-node-lease`).

## SOC2 Control Mapping

Each CIS check maps to one or more SOC2 Trust Services Criteria controls:

| SOC2 Control | Name | Mapped CIS Checks |
|-------------|------|-------------------|
| CC6.1 | Logical and Physical Access Controls | CIS-5.1.1, CIS-5.1.3, CIS-5.1.8 |
| CC6.2 | User Access Provisioning | CIS-5.1.6, CIS-5.1.5 |
| CC6.3 | Role-Based Access and Least Privilege | CIS-5.1.1, CIS-5.1.3, CIS-5.1.8 |
| CC6.6 | Security Against Threats Outside System Boundaries | CIS-5.3.2, CIS-5.2.5, CIS-5.2.6, CIS-5.2.7, CIS-5.2.8 |
| CC6.8 | Controls Against Malicious Software | CIS-5.2.3, CIS-5.2.1, CIS-5.2.2, CIS-5.2.4, CIS-5.2.13, CIS-5.7.2, CIS-5.7.3 |
| CC7.1 | Detect and Monitor Anomalies | CIS-5.2.3, CIS-5.3.2, CIS-5.7.4 |
| CC7.2 | Monitor System Components for Anomalies | CIS-5.2.3, CIS-5.3.2 |
| CC7.3 | Evaluate Security Events | CIS-5.2.3, CIS-5.3.2 |
| CC8.1 | Change Management | CIS-5.1.2, CIS-5.4.1 |

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
| **EKS** | `eks.amazonaws.com/*` node labels | `UpdateClusterConfig` via AWS SDK — enables all 5 log types | Implemented |
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

# Clean build artifacts
make clean
```

See [docs/developing.md](docs/developing.md) for details on adding new checks and extending the codebase.

## Architecture

```
cmd/varax/          CLI entry points (scan, status, operator, version)
api/v1alpha1/            CRD type definitions (ComplianceConfig)
internal/controller/     Kubernetes controller reconciliation loop
pkg/scanning/            Check interface, registry, and scan runner
pkg/scanning/checks/     20 CIS Benchmark check implementations
pkg/compliance/          SOC2 control definitions, mapper, and scorer
pkg/providers/           Cloud provider detection and audit log enablement
pkg/cli/                 Terminal UI components (Lipgloss styles, score gauge, tables)
pkg/metrics/             Prometheus metric definitions
pkg/storage/             BoltDB scan result persistence
pkg/models/              Shared data types
helm/varax/         Helm chart for Kubernetes deployment
```

See [docs/architecture.md](docs/architecture.md) for the full system design.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
