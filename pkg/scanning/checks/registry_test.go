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

func TestRegisterAll_AllHaveBenchmark(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterAll(registry)

	for _, check := range registry.All() {
		assert.NotEmpty(t, check.ID(), "check has empty ID")
		assert.NotEmpty(t, check.Description(), "check %s has empty description", check.ID())
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
}

func TestRegisterPSS_RegistersExpectedCount(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterPSS(registry)

	checks := registry.All()
	assert.Equal(t, 5, len(checks), "RegisterPSS should register 5 checks")
}

func TestRegisterRBAC_RegistersExpectedCount(t *testing.T) {
	registry := scanning.NewRegistry()
	RegisterRBAC(registry)

	checks := registry.All()
	assert.Equal(t, 4, len(checks), "RegisterRBAC should register 4 checks")
}
