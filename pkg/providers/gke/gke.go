package gke

import (
	"context"
	"fmt"
)

// GKEClient abstracts the GCP GKE API calls for testing.
type GKEClient interface {
	GetCluster(ctx context.Context, project, location, clusterName string) (*ClusterInfo, error)
	UpdateLoggingService(ctx context.Context, project, location, clusterName, loggingService string) error
}

// ClusterInfo represents relevant GKE cluster configuration.
type ClusterInfo struct {
	LoggingService    string
	MonitoringService string
}

// GKEProvider implements AuditLogProvider for GCP GKE clusters.
type GKEProvider struct {
	client      GKEClient
	project     string
	location    string
	clusterName string
}

// NewGKEProviderWithClient creates a provider with a custom GKE client (for testing).
func NewGKEProviderWithClient(client GKEClient, project, location, clusterName string) *GKEProvider {
	return &GKEProvider{
		client:      client,
		project:     project,
		location:    location,
		clusterName: clusterName,
	}
}

const requiredLoggingService = "logging.googleapis.com/kubernetes"

// IsAuditLoggingEnabled checks whether the GKE cluster has Kubernetes logging enabled.
// GKE clusters have admin activity audit logs on by default. This checks that the
// loggingService is set to the Kubernetes-specific logging service for full audit coverage.
func (p *GKEProvider) IsAuditLoggingEnabled(ctx context.Context) (bool, error) {
	cluster, err := p.client.GetCluster(ctx, p.project, p.location, p.clusterName)
	if err != nil {
		return false, fmt.Errorf("failed to get GKE cluster %q: %w", p.clusterName, err)
	}

	return cluster.LoggingService == requiredLoggingService, nil
}

// EnableAuditLogging sets the GKE cluster's logging service to the Kubernetes logging service.
func (p *GKEProvider) EnableAuditLogging(ctx context.Context) error {
	enabled, err := p.IsAuditLoggingEnabled(ctx)
	if err != nil {
		return err
	}
	if enabled {
		return nil
	}

	err = p.client.UpdateLoggingService(ctx, p.project, p.location, p.clusterName, requiredLoggingService)
	if err != nil {
		return fmt.Errorf("failed to enable audit logging on GKE cluster %q: %w", p.clusterName, err)
	}

	return nil
}
