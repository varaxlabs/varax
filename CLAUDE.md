# Varax - Project Instructions

## Build & Test Commands

```bash
make build          # Build binary to bin/varax
make test           # Run tests with -race and coverage (prints total %)
make fmt            # Format all Go code
make vet            # Run go vet
make lint           # Run golangci-lint
make generate       # Regenerate deep copy functions (requires controller-gen)
make manifests      # Regenerate CRD and RBAC manifests
make docker-build   # Build Docker image
make clean          # Remove build artifacts
```

Run a single package's tests:
```bash
go test ./pkg/scanning/checks/ -v -count=1
```

## Project Structure

```
cmd/varax/          CLI commands (main.go, scan.go, status.go, operator.go, version.go)
api/v1alpha1/            CRD types + generated deep copy (ComplianceConfig)
internal/controller/     Reconciler (runs scan, maps compliance, updates CRD status, records metrics)
pkg/scanning/            Check interface, Registry, ScanRunner with panic recovery
pkg/scanning/checks/     Each CIS check in its own file + test file (20 checks)
pkg/compliance/          SOC2 controls, CIS->SOC2 mapper, scorer
pkg/providers/           AuditLogProvider interface + DetectProvider
pkg/providers/aws/       EKS audit log enablement via AWS SDK v2
pkg/providers/selfhosted/ Self-hosted audit policy ConfigMap creation
pkg/cli/                 Lipgloss styles, ScoreGauge, SummaryBox, ControlTable, JSON output
pkg/metrics/             Prometheus gauge definitions
pkg/storage/             BoltDB Store interface + implementation
pkg/models/              Shared types (CheckResult, ScanResult, ComplianceResult, etc.)
helm/varax/         Helm chart (templates, values, CRD, NOTES.txt)
config/samples/          Sample ComplianceConfig YAML
```

## Key Architecture Decisions

- **Single binary**: CLI commands and operator share the same binary. `varax scan` runs one-shot, `varax operator` starts the controller-runtime loop.
- **Check interface**: All checks implement `scanning.Check`. Each check is a single file in `pkg/scanning/checks/` with its own `_test.go`.
- **Registry pattern**: Checks self-register via `checks.RegisterAll(registry)`. The registry supports filtering by benchmark.
- **SOC2 mapping**: `pkg/compliance/soc2_controls.go` defines controls and CIS check -> SOC2 control mappings. The mapper derives control status from check results.
- **Provider abstraction**: `providers.AuditLogProvider` interface with implementations per cloud. Provider detection reads node labels.
- **Output modes**: Three formats — styled (Lipgloss, TTY), plain (no ANSI), JSON. Auto-detected via `term.IsTerminal()`.

## Coding Conventions

- **Module**: `github.com/varax/operator`
- **Go version**: 1.25
- **Testing**: testify (assert/require), k8s fake clientset for check tests
- **Each CIS check**: One file per check named `cis_X_Y_Z_description.go` with matching `_test.go`
- **Check tests**: Use `fake.NewSimpleClientset()` with test fixtures, test pass/fail/system-namespace-skip cases
- **System namespaces**: All checks skip `kube-system`, `kube-public`, `kube-node-lease`
- **Error handling**: Checks return `StatusSkip` on API errors (non-fatal). Runner recovers from panics.
- **No external network calls** except cloud SDK for audit log enablement
- **Coverage target**: >80% (currently ~81%)

## Adding a New CIS Check

1. Create `pkg/scanning/checks/cis_X_Y_Z_name.go` implementing the `scanning.Check` interface
2. Create `pkg/scanning/checks/cis_X_Y_Z_name_test.go` with pass, fail, and system-namespace tests
3. Register it in `pkg/scanning/checks/registry.go` inside `RegisterAll()`
4. Add the check ID to the relevant SOC2 control mapping in `pkg/compliance/soc2_controls.go`
5. Run `make test` to verify

## Adding a New Cloud Provider

1. Create `pkg/providers/<provider>/` directory
2. Implement `providers.AuditLogProvider` interface (EnableAuditLogging, IsAuditLoggingEnabled)
3. Add detection case in `pkg/providers/detect.go`
4. Wire into `reconcileAuditLogging()` in `internal/controller/complianceconfig_controller.go`
5. Add SDK dependency: `go get <sdk-package>`

## CRD

API group: `compliance.varax.io/v1alpha1`
Kind: `ComplianceConfig`
The CRD YAML lives in `helm/varax/crds/complianceconfig-crd.yaml`.
Types are in `api/v1alpha1/complianceconfig_types.go`.
Deep copy is generated: `api/v1alpha1/zz_generated.deepcopy.go`.

## Dependencies

Key dependencies (see go.mod):
- `sigs.k8s.io/controller-runtime` v0.19.4 — operator framework
- `k8s.io/client-go` v0.31.4 — Kubernetes API client
- `github.com/aws/aws-sdk-go-v2` — EKS audit log enablement
- `github.com/charmbracelet/lipgloss` — terminal styling
- `github.com/spf13/cobra` — CLI framework
- `go.etcd.io/bbolt` — local storage
- `github.com/prometheus/client_golang` — metrics
