package remediators

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/remediation"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNetworkPolicyRemediator(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &NetworkPolicyRemediator{}
	assert.Equal(t, "CIS-5.3.2", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Namespace", Name: "app"},
			Field:    "networkPolicies",
			Value:    "0",
		},
		{
			Resource: models.Resource{Kind: "Namespace", Name: "data"},
			Field:    "networkPolicies",
			Value:    "0",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Len(t, actions, 2)

	for _, a := range actions {
		assert.Equal(t, remediation.ActionCreate, a.ActionType)
		assert.Equal(t, "NetworkPolicy", a.TargetKind)
		assert.Equal(t, "varax-default-deny", a.TargetName)
		assert.NotEmpty(t, a.PatchJSON)
	}
}

func TestNetworkPolicyRemediator_Deduplicates(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &NetworkPolicyRemediator{}
	evidence := []models.Evidence{
		{Resource: models.Resource{Kind: "Namespace", Name: "app"}},
		{Resource: models.Resource{Kind: "Namespace", Name: "app"}},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Len(t, actions, 1)
}

func TestNetworkPolicyRemediator_SkipsNonNamespace(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &NetworkPolicyRemediator{}
	evidence := []models.Evidence{
		{Resource: models.Resource{Kind: "Pod", Name: "pod1", Namespace: "app"}},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Empty(t, actions)
}
