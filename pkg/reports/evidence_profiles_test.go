package reports

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/evidence"
)

func TestFilterEvidenceByProfile_TypeMatching(t *testing.T) {
	bundle := &evidence.EvidenceBundle{
		Items: []evidence.EvidenceItem{
			{Category: "RBAC", Type: "rbac-cluster-admin", Description: "cluster admin"},
			{Category: "RBAC", Type: "rbac-sa-token-mount", Description: "SA tokens"},
			{Category: "RBAC", Type: "rbac-namespace-scope", Description: "scope ratio"},
			{Category: "Network", Type: "network-policy-coverage", Description: "net policies"},
		},
	}

	// CC6.1 should get rbac-cluster-admin and rbac-sa-token-mount, NOT rbac-namespace-scope
	items := FilterEvidenceByProfile(bundle, "CC6.1")
	assert.Len(t, items, 2)
	types := make([]string, len(items))
	for i, item := range items {
		types[i] = item.Type
	}
	assert.Contains(t, types, "rbac-cluster-admin")
	assert.Contains(t, types, "rbac-sa-token-mount")

	// CC6.3 should get rbac-namespace-scope, NOT rbac-cluster-admin
	items = FilterEvidenceByProfile(bundle, "CC6.3")
	assert.Len(t, items, 1)
	assert.Equal(t, "rbac-namespace-scope", items[0].Type)

	// CC6.6 should get network-policy-coverage
	items = FilterEvidenceByProfile(bundle, "CC6.6")
	assert.Len(t, items, 1)
	assert.Equal(t, "network-policy-coverage", items[0].Type)
}

func TestFilterEvidenceByProfile_CategoryFallback(t *testing.T) {
	// Items without Type should fall back to category matching
	bundle := &evidence.EvidenceBundle{
		Items: []evidence.EvidenceItem{
			{Category: "RBAC", Description: "legacy RBAC item"},
			{Category: "Network", Description: "legacy network item"},
		},
	}

	// CC6.1 has RBAC in its legacy categories
	items := FilterEvidenceByProfile(bundle, "CC6.1")
	assert.Len(t, items, 1)
	assert.Equal(t, "legacy RBAC item", items[0].Description)
}

func TestFilterEvidenceByProfile_NilBundle(t *testing.T) {
	items := FilterEvidenceByProfile(nil, "CC6.1")
	assert.Nil(t, items)
}

func TestFilterEvidenceByProfile_UnknownControl(t *testing.T) {
	bundle := &evidence.EvidenceBundle{
		Items: []evidence.EvidenceItem{
			{Category: "RBAC", Type: "rbac-cluster-admin", Description: "test"},
		},
	}
	items := FilterEvidenceByProfile(bundle, "UNKNOWN")
	assert.Nil(t, items)
}

func TestFilterEvidenceByProfile_MixedTypedAndUntyped(t *testing.T) {
	bundle := &evidence.EvidenceBundle{
		Items: []evidence.EvidenceItem{
			{Category: "RBAC", Type: "rbac-cluster-admin", Description: "typed item"},
			{Category: "RBAC", Description: "untyped RBAC item"},
		},
	}

	// CC6.1 should get the typed match via profile and the untyped match via category fallback
	items := FilterEvidenceByProfile(bundle, "CC6.1")
	assert.Len(t, items, 2)
}

func TestEvidenceProfilesForControl(t *testing.T) {
	profiles := EvidenceProfilesForControl("CC6.1")
	assert.Contains(t, profiles, "rbac-cluster-admin")
	assert.Contains(t, profiles, "rbac-sa-token-mount")

	profiles = EvidenceProfilesForControl("UNKNOWN")
	assert.Nil(t, profiles)
}

func TestAllControlsHaveProfiles(t *testing.T) {
	// Every control should have an evidence profile
	controlIDs := []string{
		"CC5.1", "CC5.2", "CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.7", "CC6.8",
		"CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5", "CC8.1", "A1.1", "A1.2",
	}
	for _, id := range controlIDs {
		profiles := EvidenceProfilesForControl(id)
		assert.NotEmpty(t, profiles, "control %s should have evidence profiles", id)
	}
}

func TestFilterEvidenceByProfile_NoTypeOverlap(t *testing.T) {
	// Verify that CC6.1 and CC6.3 don't share the same RBAC evidence
	// (which was the original problem of evidence duplication)
	now := time.Now()
	bundle := &evidence.EvidenceBundle{
		Items: []evidence.EvidenceItem{
			{Category: "RBAC", Type: "rbac-cluster-admin", Description: "admin bindings", Timestamp: now},
			{Category: "RBAC", Type: "rbac-sa-token-mount", Description: "SA tokens", Timestamp: now},
			{Category: "RBAC", Type: "rbac-namespace-scope", Description: "scope ratio", Timestamp: now},
			{Category: "RBAC", Type: "rbac-wildcard-roles", Description: "wildcards", Timestamp: now},
		},
	}

	cc61 := FilterEvidenceByProfile(bundle, "CC6.1")
	cc63 := FilterEvidenceByProfile(bundle, "CC6.3")

	// CC6.1 gets cluster-admin + sa-token-mount
	cc61Types := make(map[string]bool)
	for _, item := range cc61 {
		cc61Types[item.Type] = true
	}
	assert.True(t, cc61Types["rbac-cluster-admin"])
	assert.True(t, cc61Types["rbac-sa-token-mount"])
	assert.False(t, cc61Types["rbac-wildcard-roles"])

	// CC6.3 gets namespace-scope + wildcard-roles
	cc63Types := make(map[string]bool)
	for _, item := range cc63 {
		cc63Types[item.Type] = true
	}
	assert.True(t, cc63Types["rbac-namespace-scope"])
	assert.True(t, cc63Types["rbac-wildcard-roles"])
	assert.False(t, cc63Types["rbac-cluster-admin"])
}
