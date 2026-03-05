package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDenyServiceExternalIPsCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(apiServerPod("--enable-admission-plugins=NodeRestriction,DenyServiceExternalIPs"))
	result := (&DenyServiceExternalIPsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestDenyServiceExternalIPsCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(apiServerPod("--enable-admission-plugins=NodeRestriction"))
	result := (&DenyServiceExternalIPsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestDenyServiceExternalIPsCheck_SkipManaged(t *testing.T) {
	client := fake.NewSimpleClientset(managedNode())
	result := (&DenyServiceExternalIPsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusSkip, result.Status)
}
