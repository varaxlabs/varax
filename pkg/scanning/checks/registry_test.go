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
