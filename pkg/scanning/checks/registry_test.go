package checks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/scanning"
)

func assertCheckMetadata(t *testing.T, checks []scanning.Check, expectedBenchmark string) {
	t.Helper()
	for _, check := range checks {
		id := check.ID()
		assert.NotEmpty(t, id, "check has empty ID")
		assert.NotEmpty(t, check.Name(), "check %s has empty Name", id)
		assert.NotEmpty(t, check.Description(), "check %s has empty Description", id)
		assert.NotEmpty(t, check.Severity(), "check %s has empty Severity", id)
		if expectedBenchmark != "" {
			assert.Equal(t, expectedBenchmark, check.Benchmark(), "check %s has wrong Benchmark", id)
		} else {
			assert.NotEmpty(t, check.Benchmark(), "check %s has empty Benchmark", id)
		}
		assert.NotEmpty(t, check.Section(), "check %s has empty Section", id)
	}
}

func TestRegisterAll_RegistersChecks(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterAll(registry)

	checks := registry.All()
	assert.GreaterOrEqual(t, len(checks), 20, "expected at least 20 checks to be registered")
}

func TestRegisterAll_UniqueIDs(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterAll(registry)

	seen := make(map[string]bool)
	for _, check := range registry.All() {
		id := check.ID()
		assert.False(t, seen[id], "duplicate check ID: %s", id)
		seen[id] = true
	}
}

func TestRegisterAll_AllHaveMetadata(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterAll(registry)
	assertCheckMetadata(t, registry.All(), "")
}

func TestRegisteredChecks_ByBenchmark(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterAll(registry)

	cisChecks := registry.ByBenchmark("CIS")
	assert.GreaterOrEqual(t, len(cisChecks), 20, "expected at least 20 CIS checks")
}

func TestRegisterNSACISA_RegistersExpectedCount(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterNSACISA(registry)

	checks := registry.All()
	assert.Equal(t, 21, len(checks), "RegisterNSACISA should register 21 checks")
	assertCheckMetadata(t, checks, "NSA-CISA")
}

func TestRegisterPSS_RegistersExpectedCount(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterPSS(registry)

	checks := registry.All()
	assert.Equal(t, 5, len(checks), "RegisterPSS should register 5 checks")
	assertCheckMetadata(t, checks, "PSS")
}

func TestRegisterRBAC_RegistersExpectedCount(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterRBAC(registry)

	checks := registry.All()
	assert.Equal(t, 4, len(checks), "RegisterRBAC should register 4 checks")
	assertCheckMetadata(t, checks, "RBAC")
}

func TestRegisterAPIHygiene_RegistersChecks(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterAPIHygiene(registry)
	checks := registry.All()
	assert.GreaterOrEqual(t, len(checks), 1)
	assertCheckMetadata(t, checks, BenchmarkAPIHygiene)
}

func TestRegisterIngressHardening_RegistersChecks(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterIngressHardening(registry)
	checks := registry.All()
	assert.GreaterOrEqual(t, len(checks), 1)
	assertCheckMetadata(t, checks, BenchmarkIngressHardening)
}

func TestRegisterNamespaceGov_RegistersChecks(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterNamespaceGov(registry)
	checks := registry.All()
	assert.GreaterOrEqual(t, len(checks), 1)
	assertCheckMetadata(t, checks, BenchmarkNamespaceGov)
}

func TestRegisterSupplyChain_RegistersChecks(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterSupplyChain(registry)
	checks := registry.All()
	assert.GreaterOrEqual(t, len(checks), 1)
	assertCheckMetadata(t, checks, BenchmarkSupplyChain)
}

func TestRegisterWorkloadHygiene_RegistersChecks(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterWorkloadHygiene(registry)
	checks := registry.All()
	assert.GreaterOrEqual(t, len(checks), 1)
	assertCheckMetadata(t, checks, BenchmarkWorkloadHygiene)
}
