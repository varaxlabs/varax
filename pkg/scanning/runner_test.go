package scanning

import (
	"context"
	"testing"
	"time"

	"github.com/varax/operator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

type mockCheck struct {
	id     string
	name   string
	status models.CheckStatus
}

func (m *mockCheck) ID() string                { return m.id }
func (m *mockCheck) Name() string              { return m.name }
func (m *mockCheck) Description() string       { return "mock check" }
func (m *mockCheck) Severity() models.Severity { return models.SeverityMedium }
func (m *mockCheck) Benchmark() string         { return "MOCK" }
func (m *mockCheck) Section() string           { return "1.0" }
func (m *mockCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return models.CheckResult{
		ID:     m.id,
		Name:   m.name,
		Status: m.status,
	}
}

func TestScanRunner_RunAll(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockCheck{id: "T-1", name: "Check 1", status: models.StatusPass})
	registry.Register(&mockCheck{id: "T-2", name: "Check 2", status: models.StatusFail})
	registry.Register(&mockCheck{id: "T-3", name: "Check 3", status: models.StatusPass})

	client := fake.NewSimpleClientset()
	runner := NewScanRunner(registry, client)

	result, err := runner.RunAll(context.Background(), nil)
	require.NoError(t, err)

	assert.Len(t, result.Results, 3)
	assert.Equal(t, 3, result.Summary.TotalChecks)
	assert.Equal(t, 2, result.Summary.PassCount)
	assert.Equal(t, 1, result.Summary.FailCount)
}

func TestScanRunner_EmptyRegistry(t *testing.T) {
	registry := NewRegistry()
	client := fake.NewSimpleClientset()
	runner := NewScanRunner(registry, client)

	_, err := runner.RunAll(context.Background(), nil)
	assert.Error(t, err)
}

func TestScanRunner_ProgressCallback(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockCheck{id: "T-1", name: "Check 1", status: models.StatusPass})
	registry.Register(&mockCheck{id: "T-2", name: "Check 2", status: models.StatusPass})

	client := fake.NewSimpleClientset()
	runner := NewScanRunner(registry, client)

	var calls []int
	progress := func(completed, total int, current models.CheckResult) {
		calls = append(calls, completed)
	}

	_, err := runner.RunAll(context.Background(), progress)
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2}, calls)
}

func TestScanRunner_ContextCancellation(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockCheck{id: "T-1", name: "Check 1", status: models.StatusPass})

	client := fake.NewSimpleClientset()
	runner := NewScanRunner(registry, client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := runner.RunAll(ctx, nil)
	assert.Error(t, err)
}

type panicCheck struct{}

func (p *panicCheck) ID() string                { return "PANIC-1" }
func (p *panicCheck) Name() string              { return "Panic Check" }
func (p *panicCheck) Description() string       { return "panics" }
func (p *panicCheck) Severity() models.Severity { return models.SeverityHigh }
func (p *panicCheck) Benchmark() string         { return "TEST" }
func (p *panicCheck) Section() string           { return "0.0" }
func (p *panicCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	panic("intentional panic")
}

func TestScanRunner_PanicRecovery(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&panicCheck{})

	client := fake.NewSimpleClientset()
	runner := NewScanRunner(registry, client)

	result, err := runner.RunAll(context.Background(), nil)
	require.NoError(t, err)

	assert.Len(t, result.Results, 1)
	assert.Equal(t, models.StatusSkip, result.Results[0].Status)
	assert.Contains(t, result.Results[0].Message, "internal error")
}

func TestByBenchmark(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&mockCheck{id: "T-1", name: "CIS Check", status: models.StatusPass})
	registry.Register(&mockCheck{id: "T-2", name: "CIS Check 2", status: models.StatusFail})

	cisChecks := registry.ByBenchmark("MOCK")
	assert.Len(t, cisChecks, 2)

	otherChecks := registry.ByBenchmark("OTHER")
	assert.Len(t, otherChecks, 0)
}

func TestComputeSummary_AllStatuses(t *testing.T) {
	results := []models.CheckResult{
		{Status: models.StatusPass},
		{Status: models.StatusPass},
		{Status: models.StatusFail},
		{Status: models.StatusWarn},
		{Status: models.StatusSkip},
		{Status: models.StatusProviderManaged},
	}

	summary := computeSummary(results)
	assert.Equal(t, 6, summary.TotalChecks)
	assert.Equal(t, 2, summary.PassCount)
	assert.Equal(t, 1, summary.FailCount)
	assert.Equal(t, 1, summary.WarnCount)
	assert.Equal(t, 1, summary.SkipCount)
	assert.Equal(t, 1, summary.ProviderManagedCount)
}

func TestComputeSummary_Empty(t *testing.T) {
	summary := computeSummary([]models.CheckResult{})
	assert.Equal(t, 0, summary.TotalChecks)
}

// slowCheck simulates a check that respects context cancellation.
type slowCheck struct{}

func (s *slowCheck) ID() string                { return "SLOW-1" }
func (s *slowCheck) Name() string              { return "Slow Check" }
func (s *slowCheck) Description() string       { return "blocks until context cancelled" }
func (s *slowCheck) Severity() models.Severity { return models.SeverityMedium }
func (s *slowCheck) Benchmark() string         { return "TEST" }
func (s *slowCheck) Section() string           { return "0.0" }
func (s *slowCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	// Block until the per-check timeout fires
	<-ctx.Done()
	return models.CheckResult{
		ID:      "SLOW-1",
		Name:    "Slow Check",
		Status:  models.StatusSkip,
		Message: "timed out",
	}
}

func TestScanRunner_PerCheckTimeout(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&slowCheck{})
	registry.Register(&mockCheck{id: "T-1", name: "Fast Check", status: models.StatusPass})

	client := fake.NewSimpleClientset()
	runner := NewScanRunner(registry, client)

	start := time.Now()
	result, err := runner.RunAll(context.Background(), nil)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Len(t, result.Results, 2)
	// The slow check should have been cut off by the per-check timeout (30s),
	// not block indefinitely. Verify it completed in a reasonable time.
	assert.Less(t, elapsed, checkTimeout+5*time.Second)
	// Second check should still have run successfully
	assert.Equal(t, models.StatusPass, result.Results[1].Status)
}
