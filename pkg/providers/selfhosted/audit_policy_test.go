package selfhosted

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestIsAuditLoggingEnabled_NotFound(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewSelfHostedProvider(client)

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsAuditLoggingEnabled_Exists(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      auditPolicyConfigMap,
			Namespace: auditPolicyNamespace,
		},
		Data: map[string]string{
			auditPolicyKey: "test-policy",
		},
	}
	client := fake.NewSimpleClientset(cm)
	provider := NewSelfHostedProvider(client)

	enabled, err := provider.IsAuditLoggingEnabled(context.Background())
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestEnableAuditLogging_Creates(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewSelfHostedProvider(client)

	err := provider.EnableAuditLogging(context.Background())
	require.NoError(t, err)

	cm, err := client.CoreV1().ConfigMaps(auditPolicyNamespace).Get(context.Background(), auditPolicyConfigMap, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "varax", cm.Labels["app.kubernetes.io/managed-by"])
	assert.Contains(t, cm.Data[auditPolicyKey], "audit.k8s.io/v1")
}

func TestEnableAuditLogging_AlreadyExists(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      auditPolicyConfigMap,
			Namespace: auditPolicyNamespace,
		},
		Data: map[string]string{
			auditPolicyKey: "existing-policy",
		},
	}
	client := fake.NewSimpleClientset(cm)
	provider := NewSelfHostedProvider(client)

	err := provider.EnableAuditLogging(context.Background())
	require.NoError(t, err)

	// Verify original was not overwritten
	existing, err := client.CoreV1().ConfigMaps(auditPolicyNamespace).Get(context.Background(), auditPolicyConfigMap, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "existing-policy", existing.Data[auditPolicyKey])
}
