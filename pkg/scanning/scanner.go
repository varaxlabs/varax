package scanning

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes"
)

// Check is the interface that all compliance checks must implement.
type Check interface {
	// ID returns the unique identifier (e.g., "CIS-5.1.1").
	ID() string

	// Name returns a human-readable name.
	Name() string

	// Description returns what this check verifies.
	Description() string

	// Severity returns the severity level of findings.
	Severity() models.Severity

	// Benchmark returns the benchmark name (e.g., "CIS").
	Benchmark() string

	// Section returns the benchmark section (e.g., "5.1.1").
	Section() string

	// Run executes the check against the given Kubernetes clientset.
	Run(ctx context.Context, client kubernetes.Interface) models.CheckResult
}

// Registry holds registered compliance checks.
type Registry struct {
	checks []Check
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a check to the registry.
func (r *Registry) Register(c Check) {
	r.checks = append(r.checks, c)
}

// All returns all registered checks.
func (r *Registry) All() []Check {
	return r.checks
}

// ByBenchmark returns checks matching the given benchmark name.
func (r *Registry) ByBenchmark(benchmark string) []Check {
	var result []Check
	for _, c := range r.checks {
		if c.Benchmark() == benchmark {
			result = append(result, c)
		}
	}
	return result
}
