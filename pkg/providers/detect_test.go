package providers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDetectProvider_EKS(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ip-10-0-1-1.ec2.internal",
				Labels: map[string]string{
					"eks.amazonaws.com/nodegroup": "default",
					"kubernetes.io/os":            "linux",
				},
			},
		},
	)

	provider, err := DetectProvider(context.Background(), client)
	require.NoError(t, err)
	assert.Equal(t, ProviderEKS, provider)
}

func TestDetectProvider_AKS(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aks-default-12345678-vmss000000",
				Labels: map[string]string{
					"kubernetes.azure.com/cluster": "my-cluster",
					"kubernetes.io/os":             "linux",
				},
			},
		},
	)

	provider, err := DetectProvider(context.Background(), client)
	require.NoError(t, err)
	assert.Equal(t, ProviderAKS, provider)
}

func TestDetectProvider_GKE(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gke-my-cluster-default-pool-abc123",
				Labels: map[string]string{
					"cloud.google.com/gke-nodepool": "default-pool",
					"kubernetes.io/os":              "linux",
				},
			},
		},
	)

	provider, err := DetectProvider(context.Background(), client)
	require.NoError(t, err)
	assert.Equal(t, ProviderGKE, provider)
}

func TestDetectProvider_SelfHosted(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "worker-1",
				Labels: map[string]string{
					"kubernetes.io/os":       "linux",
					"kubernetes.io/hostname": "worker-1",
				},
			},
		},
	)

	provider, err := DetectProvider(context.Background(), client)
	require.NoError(t, err)
	assert.Equal(t, ProviderSelfHosted, provider)
}

func TestDetectProvider_NoNodes(t *testing.T) {
	client := fake.NewSimpleClientset()

	provider, err := DetectProvider(context.Background(), client)
	require.NoError(t, err)
	assert.Equal(t, ProviderSelfHosted, provider)
}
