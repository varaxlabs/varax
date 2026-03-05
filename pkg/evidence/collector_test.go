package evidence

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCollectAll(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "admin"}},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "default"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "app"},
		},
	)

	bundle, err := CollectAll(context.Background(), client)
	require.NoError(t, err)
	assert.NotNil(t, bundle)
	assert.NotEmpty(t, bundle.Items)
	assert.False(t, bundle.CollectedAt.IsZero())

	// Should have RBAC, Network, Audit, Encryption items
	categories := make(map[string]bool)
	for _, item := range bundle.Items {
		categories[item.Category] = true
	}
	assert.True(t, categories["RBAC"])
	assert.True(t, categories["Network"])
	assert.True(t, categories["Audit"])
	assert.True(t, categories["Encryption"])
}

func TestCollectRBAC(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "view"}},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-bind"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "role1", Namespace: "app"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "rb1", Namespace: "app"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa1", Namespace: "app"}},
	)

	items, err := collectRBAC(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 1)

	data := items[0].Data.(rbacSnapshot)
	assert.Equal(t, 1, data.ClusterRoleCount)
	assert.Equal(t, 1, data.ClusterRoleBindingCount)
	assert.Contains(t, data.ClusterAdminBindings, "admin-bind")
}

func TestCollectNetwork(t *testing.T) {
	client := fake.NewSimpleClientset(
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy1", Namespace: "app"},
			Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{"Ingress"}},
		},
	)

	items, err := collectNetwork(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 1)

	data := items[0].Data.(networkSnapshot)
	assert.Equal(t, 1, data.TotalPolicies)
}

func TestCollectAudit_NoAPIServer(t *testing.T) {
	client := fake.NewSimpleClientset()
	items, err := collectAudit(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Contains(t, items[0].Description, "not found")
}

func TestCollectAudit_WithAPIServer(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-master", Namespace: "kube-system"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "kube-apiserver",
			Args: []string{"--audit-log-path=/var/log/audit.log", "--audit-log-maxage=30"},
		}}},
	})

	items, err := collectAudit(context.Background(), client)
	require.NoError(t, err)
	data := items[0].Data.(auditSnapshot)
	assert.True(t, data.APIServerFound)
	assert.Equal(t, "/var/log/audit.log", data.AuditLogPath)
}

func TestCollectEncryption_NoEtcd(t *testing.T) {
	client := fake.NewSimpleClientset()
	items, err := collectEncryption(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Contains(t, items[0].Description, "etcd not found")

	data := items[0].Data.(encryptionSnapshot)
	assert.False(t, data.EtcdFound)
}

func TestCollectEncryption_WithEtcdAndAPIServer(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-master", Namespace: "kube-system"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "kube-apiserver",
				Args: []string{"--tls-cert-file=/etc/kubernetes/pki/apiserver.crt"},
			}}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "etcd-master", Namespace: "kube-system"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "etcd",
				Args: []string{
					"--cert-file=/etc/kubernetes/pki/etcd/server.crt",
					"--client-cert-auth=true",
					"--peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt",
					"--trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
				},
			}}},
		},
	)

	items, err := collectEncryption(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 1)

	data := items[0].Data.(encryptionSnapshot)
	assert.True(t, data.EtcdFound)
	assert.True(t, data.CertFileSet)
	assert.True(t, data.ClientCertAuth)
	assert.True(t, data.PeerCertFileSet)
	assert.True(t, data.TrustedCASet)
	assert.Equal(t, "Encryption/TLS configuration snapshot", items[0].Description)
}

func TestCollectEncryption_APIServerTLSCert_NoEtcd(t *testing.T) {
	// When only kube-apiserver is present (no etcd), the TLS cert file is captured
	// and etcd is reported as not found (managed cluster scenario).
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-master", Namespace: "kube-system"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "kube-apiserver",
				Args: []string{"--tls-cert-file=/etc/kubernetes/pki/apiserver.crt"},
			}}},
		},
	)

	items, err := collectEncryption(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 1)

	data := items[0].Data.(encryptionSnapshot)
	assert.False(t, data.EtcdFound)
	assert.Equal(t, "/etc/kubernetes/pki/apiserver.crt", data.TLSCertFile)
	assert.Contains(t, items[0].Description, "etcd not found")
}
