package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTokenAuthCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(apiServerPod("--anonymous-auth=false"))
	result := (&TokenAuthCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestTokenAuthCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(apiServerPod("--token-auth-file=/etc/tokens.csv"))
	result := (&TokenAuthCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestTokenAuthCheck_SkipManaged(t *testing.T) {
	client := fake.NewSimpleClientset(managedNode())
	result := (&TokenAuthCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusProviderManaged, result.Status)
}
