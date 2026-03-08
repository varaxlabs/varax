package checks

import (
	"testing"

	"github.com/varax/operator/pkg/scanning"
	"github.com/stretchr/testify/assert"
)

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

	for _, check := range registry.All() {
		id := check.ID()
		assert.NotEmpty(t, id, "check has empty ID")
		assert.NotEmpty(t, check.Name(), "check %s has empty Name", id)
		assert.NotEmpty(t, check.Description(), "check %s has empty Description", id)
		assert.NotEmpty(t, check.Severity(), "check %s has empty Severity", id)
		assert.NotEmpty(t, check.Benchmark(), "check %s has empty Benchmark", id)
		assert.NotEmpty(t, check.Section(), "check %s has empty Section", id)
	}
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
	for _, check := range checks {
		id := check.ID()
		assert.NotEmpty(t, id)
		assert.NotEmpty(t, check.Name(), "check %s has empty Name", id)
		assert.NotEmpty(t, check.Description(), "check %s has empty Description", id)
		assert.NotEmpty(t, check.Severity(), "check %s has empty Severity", id)
		assert.Equal(t, "NSA-CISA", check.Benchmark(), "check %s has wrong Benchmark", id)
		assert.NotEmpty(t, check.Section(), "check %s has empty Section", id)
	}
}

func TestRegisterPSS_RegistersExpectedCount(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterPSS(registry)

	checks := registry.All()
	assert.Equal(t, 5, len(checks), "RegisterPSS should register 5 checks")
	for _, check := range checks {
		id := check.ID()
		assert.NotEmpty(t, id)
		assert.NotEmpty(t, check.Name(), "check %s has empty Name", id)
		assert.NotEmpty(t, check.Description(), "check %s has empty Description", id)
		assert.NotEmpty(t, check.Severity(), "check %s has empty Severity", id)
		assert.Equal(t, "PSS", check.Benchmark(), "check %s has wrong Benchmark", id)
		assert.NotEmpty(t, check.Section(), "check %s has empty Section", id)
	}
}

func TestRegisterRBAC_RegistersExpectedCount(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterRBAC(registry)

	checks := registry.All()
	assert.Equal(t, 4, len(checks), "RegisterRBAC should register 4 checks")
	for _, check := range checks {
		id := check.ID()
		assert.NotEmpty(t, id)
		assert.NotEmpty(t, check.Name(), "check %s has empty Name", id)
		assert.NotEmpty(t, check.Description(), "check %s has empty Description", id)
		assert.NotEmpty(t, check.Severity(), "check %s has empty Severity", id)
		assert.Equal(t, "RBAC", check.Benchmark(), "check %s has wrong Benchmark", id)
		assert.NotEmpty(t, check.Section(), "check %s has empty Section", id)
	}
}
