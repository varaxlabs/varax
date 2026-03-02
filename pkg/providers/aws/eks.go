package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

// EKSClient abstracts the EKS API calls for testing.
type EKSClient interface {
	DescribeCluster(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	UpdateClusterConfig(ctx context.Context, params *eks.UpdateClusterConfigInput, optFns ...func(*eks.Options)) (*eks.UpdateClusterConfigOutput, error)
}

// EKSProvider implements AuditLogProvider for AWS EKS clusters.
type EKSProvider struct {
	client      EKSClient
	clusterName string
}

// NewEKSProvider creates a provider that uses the default AWS credential chain.
// clusterName is the EKS cluster name (not the ARN).
func NewEKSProvider(ctx context.Context, clusterName string) (*EKSProvider, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return &EKSProvider{
		client:      eks.NewFromConfig(cfg),
		clusterName: clusterName,
	}, nil
}

// NewEKSProviderWithClient creates a provider with a custom EKS client (for testing).
func NewEKSProviderWithClient(client EKSClient, clusterName string) *EKSProvider {
	return &EKSProvider{
		client:      client,
		clusterName: clusterName,
	}
}

// allLogTypes returns all EKS control plane log types.
func allLogTypes() []string {
	return []string{"api", "audit", "authenticator", "controllerManager", "scheduler"}
}

// IsAuditLoggingEnabled checks whether all control plane log types are enabled.
func (p *EKSProvider) IsAuditLoggingEnabled(ctx context.Context) (bool, error) {
	out, err := p.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(p.clusterName),
	})
	if err != nil {
		return false, fmt.Errorf("failed to describe cluster %q: %w", p.clusterName, err)
	}

	if out.Cluster == nil || out.Cluster.Logging == nil {
		return false, nil
	}

	enabledTypes := make(map[string]bool)
	for _, setup := range out.Cluster.Logging.ClusterLogging {
		if setup.Enabled != nil && *setup.Enabled {
			for _, lt := range setup.Types {
				enabledTypes[string(lt)] = true
			}
		}
	}

	for _, required := range allLogTypes() {
		if !enabledTypes[required] {
			return false, nil
		}
	}
	return true, nil
}

// EnableAuditLogging enables all control plane log types on the EKS cluster.
func (p *EKSProvider) EnableAuditLogging(ctx context.Context) error {
	enabled, err := p.IsAuditLoggingEnabled(ctx)
	if err != nil {
		return err
	}
	if enabled {
		return nil // already enabled
	}

	logTypes := make([]ekstypes.LogType, len(allLogTypes()))
	for i, lt := range allLogTypes() {
		logTypes[i] = ekstypes.LogType(lt)
	}

	_, err = p.client.UpdateClusterConfig(ctx, &eks.UpdateClusterConfigInput{
		Name: aws.String(p.clusterName),
		Logging: &ekstypes.Logging{
			ClusterLogging: []ekstypes.LogSetup{
				{
					Enabled: aws.Bool(true),
					Types:   logTypes,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to enable audit logging on cluster %q: %w", p.clusterName, err)
	}

	return nil
}
