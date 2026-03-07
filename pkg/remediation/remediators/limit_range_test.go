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

func TestLimitRangeRemediator(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &LimitRangeRemediator{}
	assert.Equal(t, "CIS-5.7.1", rem.CheckID())

	evidence := []models.Evidence{
		{
			Resource: models.Resource{Kind: "Namespace", Name: "app"},
		},
		{
			Resource: models.Resource{Kind: "Namespace", Name: "data"},
		},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Len(t, actions, 2)

	for _, a := range actions {
		assert.Equal(t, remediation.ActionCreate, a.ActionType)
		assert.Equal(t, "LimitRange", a.TargetKind)
		assert.Equal(t, "varax-default-limits", a.TargetName)
		assert.NotEmpty(t, a.PatchJSON)
	}
}

func TestLimitRangeRemediator_Deduplicates(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &LimitRangeRemediator{}
	evidence := []models.Evidence{
		{Resource: models.Resource{Kind: "Namespace", Name: "app"}},
		{Resource: models.Resource{Kind: "Namespace", Name: "app"}},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Len(t, actions, 1)
}

func TestLimitRangeRemediator_SkipsNonNamespace(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	rem := &LimitRangeRemediator{}
	evidence := []models.Evidence{
		{Resource: models.Resource{Kind: "Pod", Name: "pod1", Namespace: "app"}},
	}

	actions, err := rem.Plan(ctx, client, evidence)
	require.NoError(t, err)
	assert.Empty(t, actions)
}
