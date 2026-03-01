package providers

import "context"

// ProviderType represents a cloud provider hosting the Kubernetes cluster.
type ProviderType string

const (
	ProviderEKS        ProviderType = "EKS"
	ProviderAKS        ProviderType = "AKS"
	ProviderGKE        ProviderType = "GKE"
	ProviderSelfHosted ProviderType = "SelfHosted"
)

// AuditLogProvider defines methods for managing audit logging on a cloud provider.
type AuditLogProvider interface {
	// EnableAuditLogging enables audit logging for the cluster.
	EnableAuditLogging(ctx context.Context) error

	// IsAuditLoggingEnabled checks whether audit logging is currently enabled.
	IsAuditLoggingEnabled(ctx context.Context) (bool, error)
}
