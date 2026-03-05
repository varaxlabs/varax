package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes/fake"
)

func TestKubeletClientCertCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(apiServerPod("--kubelet-client-certificate=/path/cert", "--kubelet-client-key=/path/key"))
	result := (&KubeletClientCertCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestKubeletClientCertCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(apiServerPod())
	result := (&KubeletClientCertCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestKubeletClientCertCheck_SkipManaged(t *testing.T) {
	client := fake.NewSimpleClientset(managedNode())
	result := (&KubeletClientCertCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusSkip, result.Status)
}
