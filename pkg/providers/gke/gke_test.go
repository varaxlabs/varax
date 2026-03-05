package gke

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGKEClient implements GKEClient for testing.
type mockGKEClient struct {
	cluster        *ClusterInfo
	getErr         error
	updateErr      error
	updatedService string
}

func (m *mockGKEClient) GetCluster(_ context.Context, _, _, _ string) (*ClusterInfo, error) {
	return m.cluster, m.getErr
}

func (m *mockGKEClient) UpdateLoggingService(_ context.Context, _, _, _, loggingService string) error {
	m.updatedService = loggingService
	return m.updateErr
}

func TestIsAuditLoggingEnabled_KubernetesLogging(t *testing.T) {
	client := &mockGKEClient{
		cluster: &ClusterInfo{LoggingService: "logging.googleapis.com/kubernetes"},
	}
	provider := NewGKEProviderWithClient(client, "my-project", "us-central1-a", "my-cluster")

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestIsAuditLoggingEnabled_LegacyLogging(t *testing.T) {
	client := &mockGKEClient{
		cluster: &ClusterInfo{LoggingService: "logging.googleapis.com"},
	}
	provider := NewGKEProviderWithClient(client, "my-project", "us-central1-a", "my-cluster")

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_Disabled(t *testing.T) {
	client := &mockGKEClient{
		cluster: &ClusterInfo{LoggingService: "none"},
	}
	provider := NewGKEProviderWithClient(client, "my-project", "us-central1-a", "my-cluster")

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_Error(t *testing.T) {
	client := &mockGKEClient{getErr: fmt.Errorf("API error")}
	provider := NewGKEProviderWithClient(client, "my-project", "us-central1-a", "my-cluster")

	_, err := provider.IsAuditLoggingEnabled(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get GKE cluster")
}

func TestEnableAuditLogging_AlreadyEnabled(t *testing.T) {
	client := &mockGKEClient{
		cluster: &ClusterInfo{LoggingService: "logging.googleapis.com/kubernetes"},
	}
	provider := NewGKEProviderWithClient(client, "my-project", "us-central1-a", "my-cluster")

	err := provider.EnableAuditLogging(context.Background())
	require.NoError(t, err)
	assert.Empty(t, client.updatedService)
}

func TestEnableAuditLogging_Enables(t *testing.T) {
	client := &mockGKEClient{
		cluster: &ClusterInfo{LoggingService: "none"},
	}
	provider := NewGKEProviderWithClient(client, "my-project", "us-central1-a", "my-cluster")

	err := provider.EnableAuditLogging(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "logging.googleapis.com/kubernetes", client.updatedService)
}

func TestEnableAuditLogging_UpdateError(t *testing.T) {
	client := &mockGKEClient{
		cluster:   &ClusterInfo{LoggingService: "none"},
		updateErr: fmt.Errorf("forbidden"),
	}
	provider := NewGKEProviderWithClient(client, "my-project", "us-central1-a", "my-cluster")

	err := provider.EnableAuditLogging(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to enable audit logging")
}
