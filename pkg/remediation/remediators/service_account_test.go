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

func TestSATokenRemediator(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &SATokenRemediator{}
	assert.Equal(t, "CIS-5.1.6", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "ServiceAccount", Name: "default", Namespace: "app"},
			Field:    "automountServiceAccountToken",
			Value:    "true (or unset)",
		},
		{
			Resource: models.Resource{Kind: "ServiceAccount", Name: "deployer", Namespace: "app"},
			Field:    "automountServiceAccountToken",
			Value:    "true (or unset)",
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Len(t, actions, 2)

	for _, a := range actions {
		assert.Equal(t, remediation.ActionPatch, a.ActionType)
		assert.Equal(t, "ServiceAccount", a.TargetKind)
		assert.Contains(t, string(a.PatchJSON), "automountServiceAccountToken")
	}
}

func TestSATokenRemediator_Deduplicates(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &SATokenRemediator{}
	evidence := []models.Evidence{
		{Resource: models.Resource{Kind: "ServiceAccount", Name: "default", Namespace: "app"}},
		{Resource: models.Resource{Kind: "ServiceAccount", Name: "default", Namespace: "app"}},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Len(t, actions, 1)
}

func TestSATokenRemediator_SkipsNonSA(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &SATokenRemediator{}
	evidence := []models.Evidence{
		{Resource: models.Resource{Kind: "Pod", Name: "pod1", Namespace: "app"}},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Empty(t, actions)
}
