# Developer Guide

## Prerequisites

- Go 1.23+
- A Kubernetes cluster (kind, minikube, or remote) for integration testing
- `controller-gen` for CRD/deepcopy generation: `go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest`
- `golangci-lint` for linting (optional): `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`

## Building

```bash
# Build the binary (output: bin/varax)
make build

# Build Docker image
make docker-build
```

The build injects version information via ldflags:

```bash
# Version from git tags (or "dev" if no tags)
# Commit from git HEAD
# BuildTime from current UTC time
```

## Testing

```bash
# Full test suite with race detector and coverage
make test

# Single package
go test ./pkg/scanning/checks/ -v -count=1

# With coverage profile
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out | tail -1    # Summary
go tool cover -html=coverage.out               # Browser view
```

Coverage target: **>80%** (currently ~81%).

## Running Locally

### One-shot scan against a cluster

```bash
# Uses default kubeconfig (~/.kube/config)
./bin/varax scan

# Explicit kubeconfig
./bin/varax scan --kubeconfig /path/to/config

# JSON output for piping to jq
./bin/varax scan -o json | jq '.compliance.score'
```

### Run the operator locally (outside cluster)

```bash
# Ensure a ComplianceConfig CR exists in your cluster
kubectl apply -f config/samples/complianceconfig_soc2.yaml

# Start the operator (uses your kubeconfig)
./bin/varax operator --metrics-bind-address :8080

# In another terminal, check metrics
curl -s http://localhost:8080/metrics | grep varax
```

## Adding a New CIS Check

Each check lives in a single file in `pkg/scanning/checks/`. Follow this pattern:

### 1. Create the check file

Create `pkg/scanning/checks/cis_X_Y_Z_description.go`:

```go
package checks

import (
    "context"

    "github.com/varax/operator/pkg/models"
    "github.com/varax/operator/pkg/scanning"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

type cisXYZDescription struct{}

func init() {
    // Do NOT register here — registration happens in registry.go
}

func (c *cisXYZDescription) ID() string          { return "CIS-5.X.Y" }
func (c *cisXYZDescription) Name() string         { return "Human readable name" }
func (c *cisXYZDescription) Description() string  { return "What this check verifies" }
func (c *cisXYZDescription) Severity() models.Severity { return models.SeverityHigh }
func (c *cisXYZDescription) Benchmark() string    { return "CIS" }
func (c *cisXYZDescription) Section() string      { return "5.X.Y" }

func (c *cisXYZDescription) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
    result := models.CheckResult{
        ID:          c.ID(),
        Name:        c.Name(),
        Description: c.Description(),
        Benchmark:   c.Benchmark(),
        Section:     c.Section(),
        Severity:    c.Severity(),
    }

    // Query the Kubernetes API
    items, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
    if err != nil {
        result.Status = models.StatusSkip
        result.Message = "Failed to list pods: " + err.Error()
        return result
    }

    // Check each item, skip system namespaces
    for _, item := range items.Items {
        ns := item.Namespace
        if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" {
            continue
        }

        // Your check logic here
        if violationDetected {
            result.Evidence = append(result.Evidence, models.Evidence{
                Message: "Description of the violation",
                Resource: models.Resource{
                    Kind:      "Pod",
                    Name:      item.Name,
                    Namespace: ns,
                },
                Field: "spec.fieldName",
                Value: "actual value",
            })
        }
    }

    if len(result.Evidence) > 0 {
        result.Status = models.StatusFail
        result.Message = fmt.Sprintf("Found %d violation(s)", len(result.Evidence))
    } else {
        result.Status = models.StatusPass
        result.Message = "All items comply"
    }

    return result
}
```

### 2. Create the test file

Create `pkg/scanning/checks/cis_X_Y_Z_description_test.go`:

```go
package checks

import (
    "context"
    "testing"

    "github.com/varax/operator/pkg/models"
    "github.com/stretchr/testify/assert"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes/fake"
)

func TestCisXYZ_Pass(t *testing.T) {
    // Create compliant resources
    pod := &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{Name: "good-pod", Namespace: "default"},
        Spec: corev1.PodSpec{/* compliant config */},
    }
    client := fake.NewSimpleClientset(pod)

    check := &cisXYZDescription{}
    result := check.Run(context.Background(), client)

    assert.Equal(t, models.StatusPass, result.Status)
    assert.Empty(t, result.Evidence)
}

func TestCisXYZ_Fail(t *testing.T) {
    // Create non-compliant resources
    pod := &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
        Spec: corev1.PodSpec{/* non-compliant config */},
    }
    client := fake.NewSimpleClientset(pod)

    check := &cisXYZDescription{}
    result := check.Run(context.Background(), client)

    assert.Equal(t, models.StatusFail, result.Status)
    assert.NotEmpty(t, result.Evidence)
}

func TestCisXYZ_SkipsSystemNamespace(t *testing.T) {
    // Non-compliant resource in kube-system should be ignored
    pod := &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
        Spec: corev1.PodSpec{/* non-compliant config */},
    }
    client := fake.NewSimpleClientset(pod)

    check := &cisXYZDescription{}
    result := check.Run(context.Background(), client)

    assert.Equal(t, models.StatusPass, result.Status)
}
```

### 3. Register the check

Add to `pkg/scanning/checks/registry.go`:

```go
func RegisterAll(registry *scanning.Registry) {
    // ... existing checks ...
    registry.Register(&cisXYZDescription{})
}
```

### 4. Add SOC2 mapping

Edit `pkg/compliance/soc2_controls.go` to add your check ID to the relevant control mapping:

```go
{ControlID: "CC6.1", CheckIDs: []string{"CIS-5.1.1", "CIS-5.1.3", "CIS-5.1.8", "CIS-5.X.Y"}},
```

### 5. Verify

```bash
make test
```

## Adding a New Cloud Provider

### 1. Create the provider package

```
pkg/providers/<name>/
    <name>.go          # AuditLogProvider implementation
    <name>_test.go     # Tests with mock client
```

Implement the `providers.AuditLogProvider` interface:

```go
type AuditLogProvider interface {
    EnableAuditLogging(ctx context.Context) error
    IsAuditLoggingEnabled(ctx context.Context) (bool, error)
}
```

See `pkg/providers/aws/eks.go` for the reference implementation pattern:
- Define a client interface for the cloud SDK (enables mock testing)
- Constructor with real client (`NewXProvider`) and test client (`NewXProviderWithClient`)
- `IsAuditLoggingEnabled` checks current state
- `EnableAuditLogging` is idempotent (no-op if already enabled)

### 2. Add provider detection

Update `pkg/providers/detect.go` if needed (existing detection covers EKS/AKS/GKE/SelfHosted via node labels).

### 3. Wire into the controller

Update `reconcileAuditLogging()` in `internal/controller/complianceconfig_controller.go`:

```go
case providers.ProviderAKS:
    auditProvider = aksprovider.NewAKSProvider(ctx, ...)
```

### 4. Add SDK dependency

```bash
go get <cloud-sdk-package>
go mod tidy
```

## Adding a New Compliance Framework

The architecture supports multiple frameworks. To add one (e.g., HIPAA):

1. Create `pkg/compliance/hipaa_controls.go` with `HIPAAControls()` and `HIPAAMappings()`
2. Create a mapper constructor `NewHIPAAMapper()` in `mapper.go` (or a new file)
3. Update the CLI and controller to select the mapper based on the `framework` field
4. Add the framework to the CRD enum validation in `api/v1alpha1/complianceconfig_types.go`
5. Regenerate with `make generate`

## Code Generation

```bash
# Regenerate deep copy functions after modifying api/v1alpha1/ types
make generate

# Regenerate CRD manifests and RBAC after modifying kubebuilder markers
make manifests
```

## Project Conventions

- **One check per file** — `cis_X_Y_Z_description.go` naming pattern
- **One test file per check** — matching `_test.go` file
- **System namespace skip** — all checks skip kube-system, kube-public, kube-node-lease
- **StatusSkip on API errors** — checks treat API failures as non-fatal
- **Evidence is structured** — every violation includes Resource (kind, name, namespace), Field, Value, Message
- **No panics** — the scan runner recovers from panics in checks
- **Testify for assertions** — use `assert` for non-fatal, `require` for fatal
- **Fake clientset for tests** — `k8s.io/client-go/kubernetes/fake`
