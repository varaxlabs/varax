package scanning

import (
	"context"
	"testing"

	"github.com/kubeshield/operator/pkg/models"
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
