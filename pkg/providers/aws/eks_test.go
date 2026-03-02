package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEKSClient implements EKSClient for testing.
type mockEKSClient struct {
	describeFunc func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	updateFunc   func(ctx context.Context, params *eks.UpdateClusterConfigInput, optFns ...func(*eks.Options)) (*eks.UpdateClusterConfigOutput, error)
}

func (m *mockEKSClient) DescribeCluster(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	return m.describeFunc(ctx, params, optFns...)
}

func (m *mockEKSClient) UpdateClusterConfig(ctx context.Context, params *eks.UpdateClusterConfigInput, optFns ...func(*eks.Options)) (*eks.UpdateClusterConfigOutput, error) {
	return m.updateFunc(ctx, params, optFns...)
}

func TestIsAuditLoggingEnabled_AllEnabled(t *testing.T) {
	mock := &mockEKSClient{
		describeFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			assert.Equal(t, "test-cluster", *params.Name)
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{
					Logging: &ekstypes.Logging{
						ClusterLogging: []ekstypes.LogSetup{
							{
								Enabled: aws.Bool(true),
								Types: []ekstypes.LogType{
									"api", "audit", "authenticator", "controllerManager", "scheduler",
								},
							},
						},
					},
				},
			}, nil
		},
	}

	provider := NewEKSProviderWithClient(mock, "test-cluster")
	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestIsAuditLoggingEnabled_PartiallyEnabled(t *testing.T) {
	mock := &mockEKSClient{
		describeFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{
					Logging: &ekstypes.Logging{
						ClusterLogging: []ekstypes.LogSetup{
							{
								Enabled: aws.Bool(true),
								Types:   []ekstypes.LogType{"api", "audit"},
							},
							{
								Enabled: aws.Bool(false),
								Types:   []ekstypes.LogType{"authenticator", "controllerManager", "scheduler"},
							},
						},
					},
				},
			}, nil
		},
	}

	provider := NewEKSProviderWithClient(mock, "test-cluster")
	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_NoneEnabled(t *testing.T) {
	mock := &mockEKSClient{
		describeFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{
					Logging: &ekstypes.Logging{
						ClusterLogging: []ekstypes.LogSetup{},
					},
				},
			}, nil
		},
	}

	provider := NewEKSProviderWithClient(mock, "test-cluster")
	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_NilLogging(t *testing.T) {
	mock := &mockEKSClient{
		describeFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{},
			}, nil
		},
	}

	provider := NewEKSProviderWithClient(mock, "test-cluster")
	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_APIError(t *testing.T) {
	mock := &mockEKSClient{
		describeFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	provider := NewEKSProviderWithClient(mock, "test-cluster")
	_, err := provider.IsAuditLoggingEnabled(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestEnableAuditLogging_Success(t *testing.T) {
	updateCalled := false
	mock := &mockEKSClient{
		describeFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{
					Logging: &ekstypes.Logging{
						ClusterLogging: []ekstypes.LogSetup{},
					},
				},
			}, nil
		},
		updateFunc: func(ctx context.Context, params *eks.UpdateClusterConfigInput, optFns ...func(*eks.Options)) (*eks.UpdateClusterConfigOutput, error) {
			updateCalled = true
			assert.Equal(t, "test-cluster", *params.Name)
			require.NotNil(t, params.Logging)
			require.Len(t, params.Logging.ClusterLogging, 1)
			assert.True(t, *params.Logging.ClusterLogging[0].Enabled)
			assert.Len(t, params.Logging.ClusterLogging[0].Types, 5)
			return &eks.UpdateClusterConfigOutput{}, nil
		},
	}

	provider := NewEKSProviderWithClient(mock, "test-cluster")
	err := provider.EnableAuditLogging(context.Background())
	require.NoError(t, err)
	assert.True(t, updateCalled)
}

func TestEnableAuditLogging_AlreadyEnabled(t *testing.T) {
	mock := &mockEKSClient{
		describeFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{
					Logging: &ekstypes.Logging{
						ClusterLogging: []ekstypes.LogSetup{
							{
								Enabled: aws.Bool(true),
								Types:   []ekstypes.LogType{"api", "audit", "authenticator", "controllerManager", "scheduler"},
							},
						},
					},
				},
			}, nil
		},
		updateFunc: func(ctx context.Context, params *eks.UpdateClusterConfigInput, optFns ...func(*eks.Options)) (*eks.UpdateClusterConfigOutput, error) {
			t.Fatal("UpdateClusterConfig should not be called when already enabled")
			return nil, nil
		},
	}

	provider := NewEKSProviderWithClient(mock, "test-cluster")
	err := provider.EnableAuditLogging(context.Background())
	require.NoError(t, err)
}

func TestEnableAuditLogging_UpdateError(t *testing.T) {
	mock := &mockEKSClient{
		describeFunc: func(ctx context.Context, params *eks.DescribeClusterInput, optFns ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
			return &eks.DescribeClusterOutput{
				Cluster: &ekstypes.Cluster{
					Logging: &ekstypes.Logging{
						ClusterLogging: []ekstypes.LogSetup{},
					},
				},
			}, nil
		},
		updateFunc: func(ctx context.Context, params *eks.UpdateClusterConfigInput, optFns ...func(*eks.Options)) (*eks.UpdateClusterConfigOutput, error) {
			return nil, errors.New("insufficient permissions")
		},
	}

	provider := NewEKSProviderWithClient(mock, "test-cluster")
	err := provider.EnableAuditLogging(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}
