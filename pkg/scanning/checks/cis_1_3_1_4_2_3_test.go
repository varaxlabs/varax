package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func controlPlanePod(component string, args ...string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: component + "-master", Namespace: "kube-system"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    component,
				Command: []string{component},
				Args:    args,
			}},
		},
	}
}

func TestControllerManagerChecks(t *testing.T) {
	tests := []apiServerCheckTest{
		{check: &CMTerminatedPodGCCheck{}, passArgs: []string{"--terminated-pod-gc-threshold=100"}, failArgs: []string{}},
		{check: &CMProfilingCheck{}, passArgs: []string{"--profiling=false"}, failArgs: []string{"--profiling=true"}},
		{check: &CMSACredentialsCheck{}, passArgs: []string{"--use-service-account-credentials=true"}, failArgs: []string{}},
		{check: &CMSAPrivateKeyCheck{}, passArgs: []string{"--service-account-private-key-file=/path/key"}, failArgs: []string{}},
		{check: &CMRootCACheck{}, passArgs: []string{"--root-ca-file=/path/ca"}, failArgs: []string{}},
		{check: &CMBindAddressCheck{}, passArgs: []string{"--bind-address=127.0.0.1"}, failArgs: []string{"--bind-address=0.0.0.0"}},
	}

	for _, tt := range tests {
		t.Run(tt.check.ID()+"_Pass", func(t *testing.T) {
			client := fake.NewSimpleClientset(controlPlanePod("kube-controller-manager", tt.passArgs...))
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusPass, result.Status)
		})
		t.Run(tt.check.ID()+"_Fail", func(t *testing.T) {
			client := fake.NewSimpleClientset(controlPlanePod("kube-controller-manager", tt.failArgs...))
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusFail, result.Status)
		})
		t.Run(tt.check.ID()+"_SkipManaged", func(t *testing.T) {
			client := fake.NewSimpleClientset(managedNode())
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusSkip, result.Status)
		})
	}
}

func TestSchedulerChecks(t *testing.T) {
	tests := []apiServerCheckTest{
		{check: &SchedulerProfilingCheck{}, passArgs: []string{"--profiling=false"}, failArgs: []string{"--profiling=true"}},
		{check: &SchedulerBindAddressCheck{}, passArgs: []string{"--bind-address=127.0.0.1"}, failArgs: []string{"--bind-address=0.0.0.0"}},
	}

	for _, tt := range tests {
		t.Run(tt.check.ID()+"_Pass", func(t *testing.T) {
			client := fake.NewSimpleClientset(controlPlanePod("kube-scheduler", tt.passArgs...))
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusPass, result.Status)
		})
		t.Run(tt.check.ID()+"_Fail", func(t *testing.T) {
			client := fake.NewSimpleClientset(controlPlanePod("kube-scheduler", tt.failArgs...))
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusFail, result.Status)
		})
	}
}

func TestEtcdChecks(t *testing.T) {
	tests := []apiServerCheckTest{
		{check: &EtcdCertFileCheck{}, passArgs: []string{"--cert-file=/path", "--key-file=/path"}, failArgs: []string{}},
		{check: &EtcdClientCertAuthCheck{}, passArgs: []string{"--client-cert-auth=true"}, failArgs: []string{}},
		{check: &EtcdAutoTLSCheck{}, passArgs: []string{}, failArgs: []string{"--auto-tls=true"}},
		{check: &EtcdPeerCertCheck{}, passArgs: []string{"--peer-cert-file=/path", "--peer-key-file=/path"}, failArgs: []string{}},
		{check: &EtcdPeerClientCertAuthCheck{}, passArgs: []string{"--peer-client-cert-auth=true"}, failArgs: []string{}},
		{check: &EtcdPeerAutoTLSCheck{}, passArgs: []string{}, failArgs: []string{"--peer-auto-tls=true"}},
		{check: &EtcdUniqueCACheck{}, passArgs: []string{"--trusted-ca-file=/path"}, failArgs: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.check.ID()+"_Pass", func(t *testing.T) {
			client := fake.NewSimpleClientset(controlPlanePod("etcd", tt.passArgs...))
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusPass, result.Status)
		})
		t.Run(tt.check.ID()+"_Fail", func(t *testing.T) {
			client := fake.NewSimpleClientset(controlPlanePod("etcd", tt.failArgs...))
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusFail, result.Status)
		})
	}
}

func TestControlPlaneConfigChecks(t *testing.T) {
	t.Run("CIS-3.1_Pass", func(t *testing.T) {
		client := fake.NewSimpleClientset(apiServerPod())
		result := (&NoStaticTokensCheck{}).Run(context.Background(), client)
		assert.Equal(t, models.StatusPass, result.Status)
	})
	t.Run("CIS-3.1_Fail", func(t *testing.T) {
		client := fake.NewSimpleClientset(apiServerPod("--token-auth-file=/etc/tokens"))
		result := (&NoStaticTokensCheck{}).Run(context.Background(), client)
		assert.Equal(t, models.StatusFail, result.Status)
	})
	t.Run("CIS-3.2_Pass", func(t *testing.T) {
		client := fake.NewSimpleClientset(apiServerPod("--audit-policy-file=/etc/audit.yaml"))
		result := (&AuditPolicyCheck{}).Run(context.Background(), client)
		assert.Equal(t, models.StatusPass, result.Status)
	})
	t.Run("CIS-3.2_Fail", func(t *testing.T) {
		client := fake.NewSimpleClientset(apiServerPod())
		result := (&AuditPolicyCheck{}).Run(context.Background(), client)
		assert.Equal(t, models.StatusFail, result.Status)
	})
}

func TestKubeletChecks_ManagedCluster(t *testing.T) {
	checks := []scanning.Check{
		KubeletAnonAuthCheck, KubeletAuthModeCheck, KubeletClientCertificateCheck,
		KubeletReadOnlyPortCheck, KubeletStreamingCheck,
	}
	for _, chk := range checks {
		t.Run(chk.ID()+"_ManagedPass", func(t *testing.T) {
			client := fake.NewSimpleClientset(managedNode())
			result := chk.Run(context.Background(), client)
			assert.Equal(t, models.StatusPass, result.Status)
		})
	}
}

func TestKubeletChecks_SelfHostedWarn(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-1", Labels: map[string]string{"kubernetes.io/os": "linux"}},
	}
	client := fake.NewSimpleClientset(node)
	result := KubeletAnonAuthCheck.Run(context.Background(), client)
	assert.Equal(t, models.StatusWarn, result.Status)
}

func TestSection5Checks(t *testing.T) {
	t.Run("CIS-5.1.4_Pass", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app-1"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app-2"}},
		)
		result := (&NamespaceBoundariesCheck{}).Run(context.Background(), client)
		assert.Equal(t, models.StatusPass, result.Status)
	})

	t.Run("CIS-5.3.1_Pass", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		result := (&CNINetworkPolicyCheck{}).Run(context.Background(), client)
		assert.Equal(t, models.StatusPass, result.Status)
	})
}

func TestContainsFeatureGate(t *testing.T) {
	assert.True(t, containsFeatureGate("RotateKubeletServerCertificate=true,PodSecurity=true", "RotateKubeletServerCertificate", "true"))
	assert.False(t, containsFeatureGate("PodSecurity=true", "RotateKubeletServerCertificate", "true"))
	assert.False(t, containsFeatureGate("", "RotateKubeletServerCertificate", "true"))
}
