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

func boolPtr(b bool) *bool { return &b }

func TestCollectAll(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "admin"}},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "admin"}},
		},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
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
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:masters"}},
		},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "role1", Namespace: "app"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "rb1", Namespace: "app"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa1", Namespace: "app"}},
	)

	items, err := collectRBAC(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 3) // rbac-cluster-admin, rbac-sa-token-mount, rbac-namespace-scope

	// Verify types
	assert.Equal(t, "rbac-cluster-admin", items[0].Type)
	assert.Equal(t, "rbac-sa-token-mount", items[1].Type)
	assert.Equal(t, "rbac-namespace-scope", items[2].Type)

	// Verify SHA256 hashes are present and valid hex
	for _, item := range items {
		assert.NotEmpty(t, item.SHA256)
		assert.Len(t, item.SHA256, 64) // hex-encoded SHA256
	}

	// Verify RBAC snapshot data
	data := items[0].Data.(RBACSnapshot)
	assert.Equal(t, 1, data.ClusterRoleCount)
	assert.Equal(t, 1, data.ClusterRoleBindingCount)
	require.Len(t, data.ClusterAdminBindings, 1)
	assert.Equal(t, "admin-bind", data.ClusterAdminBindings[0].Name)
	assert.Equal(t, "system:masters", data.ClusterAdminBindings[0].Subject)
	assert.Equal(t, "Group", data.ClusterAdminBindings[0].Type)

	// Verify SA token mount data
	saData := items[1].Data.(SATokenMountSnapshot)
	assert.Equal(t, 1, saData.NamespacesAudited)
	assert.Equal(t, 0, saData.AutoMountCount)

	// Verify namespace scope data
	scopeData := items[2].Data.(NamespaceScopeSnapshot)
	assert.Equal(t, 1, scopeData.NamespaceScopedCount)
	assert.Equal(t, 1, scopeData.ClusterScopedCount)
}

func TestCollectRBAC_WildcardDetection(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "overprivileged"},
			Rules: []rbacv1.PolicyRule{
				{Resources: []string{"*"}, Verbs: []string{"get"}},
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-role"},
			Rules: []rbacv1.PolicyRule{
				{Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
			},
		},
	)

	items, err := collectRBAC(context.Background(), client)
	require.NoError(t, err)

	data := items[0].Data.(RBACSnapshot)
	assert.Equal(t, 2, data.ClusterRoleCount)
	assert.Contains(t, data.WildcardRoles, "overprivileged")
	assert.NotContains(t, data.WildcardRoles, "safe-role")
}

func TestCollectRBAC_SAAutoMount(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: "app"},
			AutomountServiceAccountToken: boolPtr(true),
		},
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "worker", Namespace: "app"},
			AutomountServiceAccountToken: boolPtr(false),
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "other"},
			// nil means not explicitly set
		},
	)

	items, err := collectRBAC(context.Background(), client)
	require.NoError(t, err)

	saData := items[1].Data.(SATokenMountSnapshot)
	assert.Equal(t, 2, saData.NamespacesAudited)
	assert.Equal(t, 1, saData.AutoMountCount)
	assert.Contains(t, saData.AutoMountAccounts, "app/default")
}

func TestCollectNetwork(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "unprotected"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy1", Namespace: "app"},
			Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{"Ingress"}},
		},
	)

	items, err := collectNetwork(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 2) // network-policy-coverage, default-deny-status

	assert.Equal(t, "network-policy-coverage", items[0].Type)
	assert.Equal(t, "default-deny-status", items[1].Type)

	// Verify SHA256
	for _, item := range items {
		assert.NotEmpty(t, item.SHA256)
		assert.Len(t, item.SHA256, 64)
	}

	data := items[0].Data.(NetworkSnapshot)
	assert.Equal(t, 1, data.TotalPolicies)

	denyData := items[1].Data.(DefaultDenySnapshot)
	assert.Equal(t, 2, denyData.TotalNamespaces)
	// policy1 has empty podSelector + no ingress/egress rules = default-deny
	assert.Equal(t, 1, denyData.NamespacesWithDeny)
	assert.Contains(t, denyData.NamespacesWithoutDeny, "unprotected")
	assert.NotContains(t, denyData.NamespacesWithoutDeny, "app")
}

func TestCollectNetwork_DefaultDeny(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "secure"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "secure"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{}, // empty = select all
				PolicyTypes: []networkingv1.PolicyType{"Ingress", "Egress"},
				// No Ingress or Egress rules = deny all
			},
		},
	)

	items, err := collectNetwork(context.Background(), client)
	require.NoError(t, err)

	denyData := items[1].Data.(DefaultDenySnapshot)
	assert.Equal(t, 1, denyData.NamespacesWithDeny)
	assert.Empty(t, denyData.NamespacesWithoutDeny)
}

func TestCollectAudit_NoAPIServer(t *testing.T) {
	client := fake.NewSimpleClientset()
	items, err := collectAudit(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Contains(t, items[0].Description, "not found")
	assert.NotEmpty(t, items[0].SHA256)
	assert.Equal(t, "audit-logging", items[0].Type)
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
	data := items[0].Data.(AuditSnapshot)
	assert.True(t, data.APIServerFound)
	assert.Equal(t, "/var/log/audit.log", data.AuditLogPath)
	assert.NotEmpty(t, items[0].SHA256)
}

func TestCollectEncryption_NoEtcd(t *testing.T) {
	client := fake.NewSimpleClientset()
	items, err := collectEncryption(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Contains(t, items[0].Description, "etcd not found")
	assert.NotEmpty(t, items[0].SHA256)
	assert.Equal(t, "encryption-tls", items[0].Type)

	data := items[0].Data.(EncryptionSnapshot)
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

	data := items[0].Data.(EncryptionSnapshot)
	assert.True(t, data.EtcdFound)
	assert.True(t, data.CertFileSet)
	assert.True(t, data.ClientCertAuth)
	assert.True(t, data.PeerCertFileSet)
	assert.True(t, data.TrustedCASet)
	assert.Equal(t, "Encryption/TLS configuration snapshot", items[0].Description)
	assert.NotEmpty(t, items[0].SHA256)
}

func TestCollectEncryption_APIServerTLSCert_NoEtcd(t *testing.T) {
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

	data := items[0].Data.(EncryptionSnapshot)
	assert.False(t, data.EtcdFound)
	assert.Equal(t, "/etc/kubernetes/pki/apiserver.crt", data.TLSCertFile)
	assert.Contains(t, items[0].Description, "etcd not found")
}

func TestComputeSHA256(t *testing.T) {
	data := map[string]string{"key": "value"}
	hash := computeSHA256(data)
	assert.Len(t, hash, 64)

	// Same data produces same hash
	hash2 := computeSHA256(data)
	assert.Equal(t, hash, hash2)

	// Different data produces different hash
	hash3 := computeSHA256(map[string]string{"key": "other"})
	assert.NotEqual(t, hash, hash3)
}
