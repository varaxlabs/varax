package azure

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAKSClient implements AKSClient for testing.
type mockAKSClient struct {
	settings    []DiagnosticSetting
	getErr      error
	createErr   error
	createdSetting *DiagnosticSetting
}

func (m *mockAKSClient) GetDiagnosticSettings(_ context.Context, _ string) ([]DiagnosticSetting, error) {
	return m.settings, m.getErr
}

func (m *mockAKSClient) CreateOrUpdateDiagnosticSetting(_ context.Context, _ string, setting DiagnosticSetting) error {
	m.createdSetting = &setting
	return m.createErr
}

func TestIsAuditLoggingEnabled_AllEnabled(t *testing.T) {
	client := &mockAKSClient{
		settings: []DiagnosticSetting{
			{Name: "audit", Categories: []string{"kube-audit", "kube-audit-admin", "guard"}, Enabled: true},
		},
	}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestIsAuditLoggingEnabled_MissingCategory(t *testing.T) {
	client := &mockAKSClient{
		settings: []DiagnosticSetting{
			{Name: "audit", Categories: []string{"kube-audit"}, Enabled: true},
		},
	}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_Disabled(t *testing.T) {
	client := &mockAKSClient{
		settings: []DiagnosticSetting{
			{Name: "audit", Categories: []string{"kube-audit", "kube-audit-admin", "guard"}, Enabled: false},
		},
	}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_NoSettings(t *testing.T) {
	client := &mockAKSClient{}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_Error(t *testing.T) {
	client := &mockAKSClient{getErr: fmt.Errorf("API error")}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	_, err := provider.IsAuditLoggingEnabled(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get diagnostic settings")
}

func TestIsAuditLoggingEnabled_MultipleSettings(t *testing.T) {
	client := &mockAKSClient{
		settings: []DiagnosticSetting{
			{Name: "audit-1", Categories: []string{"kube-audit"}, Enabled: true},
			{Name: "audit-2", Categories: []string{"kube-audit-admin", "guard"}, Enabled: true},
		},
	}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestEnableAuditLogging_AlreadyEnabled(t *testing.T) {
	client := &mockAKSClient{
		settings: []DiagnosticSetting{
			{Name: "audit", Categories: []string{"kube-audit", "kube-audit-admin", "guard"}, Enabled: true},
		},
	}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	err := provider.EnableAuditLogging(context.Background())
	require.NoError(t, err)
	assert.Nil(t, client.createdSetting) // Should not create a setting
}

func TestEnableAuditLogging_Creates(t *testing.T) {
	client := &mockAKSClient{}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	err := provider.EnableAuditLogging(context.Background())
	require.NoError(t, err)
	require.NotNil(t, client.createdSetting)
	assert.Equal(t, "varax-audit-logs", client.createdSetting.Name)
	assert.ElementsMatch(t, []string{"kube-audit", "kube-audit-admin", "guard"}, client.createdSetting.Categories)
	assert.True(t, client.createdSetting.Enabled)
}

func TestEnableAuditLogging_CreateError(t *testing.T) {
	client := &mockAKSClient{createErr: fmt.Errorf("forbidden")}
	provider := NewAKSProviderWithClient(client, "sub-1", "rg-1", "cluster-1")

	err := provider.EnableAuditLogging(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to enable audit logging")
}

func TestResourceID(t *testing.T) {
	provider := NewAKSProviderWithClient(nil, "sub-123", "my-rg", "my-cluster")
	expected := "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.ContainerService/managedClusters/my-cluster"
	assert.Equal(t, expected, provider.resourceID())
}
