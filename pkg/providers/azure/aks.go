package azure

import (
	"context"
	"fmt"
)

// AKSClient abstracts the Azure AKS API calls for testing.
type AKSClient interface {
	GetDiagnosticSettings(ctx context.Context, resourceID string) ([]DiagnosticSetting, error)
	CreateOrUpdateDiagnosticSetting(ctx context.Context, resourceID string, setting DiagnosticSetting) error
}

// DiagnosticSetting represents an Azure diagnostic setting.
type DiagnosticSetting struct {
	Name       string
	Categories []string
	Enabled    bool
}

// AKSProvider implements AuditLogProvider for Azure AKS clusters.
type AKSProvider struct {
	client         AKSClient
	subscriptionID string
	resourceGroup  string
	clusterName    string
}

// NewAKSProviderWithClient creates a provider with a custom AKS client (for testing).
func NewAKSProviderWithClient(client AKSClient, subscriptionID, resourceGroup, clusterName string) *AKSProvider {
	return &AKSProvider{
		client:         client,
		subscriptionID: subscriptionID,
		resourceGroup:  resourceGroup,
		clusterName:    clusterName,
	}
}

func (p *AKSProvider) resourceID() string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s",
		p.subscriptionID, p.resourceGroup, p.clusterName)
}

// auditCategories returns the required audit log categories for AKS.
func auditCategories() []string {
	return []string{"kube-audit", "kube-audit-admin", "guard"}
}

// IsAuditLoggingEnabled checks whether diagnostic settings include audit log categories.
func (p *AKSProvider) IsAuditLoggingEnabled(ctx context.Context) (bool, error) {
	settings, err := p.client.GetDiagnosticSettings(ctx, p.resourceID())
	if err != nil {
		return false, fmt.Errorf("failed to get diagnostic settings for AKS cluster %q: %w", p.clusterName, err)
	}

	enabledCategories := make(map[string]bool)
	for _, s := range settings {
		if s.Enabled {
			for _, cat := range s.Categories {
				enabledCategories[cat] = true
			}
		}
	}

	for _, required := range auditCategories() {
		if !enabledCategories[required] {
			return false, nil
		}
	}
	return true, nil
}

// EnableAuditLogging creates or updates diagnostic settings to enable audit log categories.
func (p *AKSProvider) EnableAuditLogging(ctx context.Context) error {
	enabled, err := p.IsAuditLoggingEnabled(ctx)
	if err != nil {
		return err
	}
	if enabled {
		return nil
	}

	setting := DiagnosticSetting{
		Name:       "varax-audit-logs",
		Categories: auditCategories(),
		Enabled:    true,
	}

	err = p.client.CreateOrUpdateDiagnosticSetting(ctx, p.resourceID(), setting)
	if err != nil {
		return fmt.Errorf("failed to enable audit logging on AKS cluster %q: %w", p.clusterName, err)
	}

	return nil
}
