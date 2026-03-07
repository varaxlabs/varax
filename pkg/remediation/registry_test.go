package remediation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes"
)

type fakeRemediator struct {
	id string
}

func (f *fakeRemediator) CheckID() string { return f.id }
func (f *fakeRemediator) Plan(_ context.Context, _ kubernetes.Interface, _ []models.Evidence) ([]RemediationAction, error) {
	return nil, nil
}

func TestRemediatorRegistry(t *testing.T) {
	reg := NewRemediatorRegistry()

	assert.False(t, reg.Has("CIS-5.2.1"))
	assert.Nil(t, reg.Get("CIS-5.2.1"))

	rem := &fakeRemediator{id: "CIS-5.2.1"}
	reg.Register(rem)

	assert.True(t, reg.Has("CIS-5.2.1"))
	assert.Equal(t, rem, reg.Get("CIS-5.2.1"))
	assert.False(t, reg.Has("CIS-5.2.2"))
}
