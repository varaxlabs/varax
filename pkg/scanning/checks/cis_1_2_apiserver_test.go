package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes/fake"
)

// apiServerCheckTest defines a table-driven test case for API server checks.
type apiServerCheckTest struct {
	check    scanning.Check
	passArgs []string
	failArgs []string
}

func TestAPIServerChecks_PassFailSkip(t *testing.T) {
	tests := []apiServerCheckTest{
		{
			check:    &KubeletCACheck{},
			passArgs: []string{"--kubelet-certificate-authority=/path/ca"},
			failArgs: []string{},
		},
		{
			check:    &NoAlwaysAllowCheck{},
			passArgs: []string{"--authorization-mode=Node,RBAC"},
			failArgs: []string{"--authorization-mode=AlwaysAllow"},
		},
		{
			check:    &NodeAuthCheck{},
			passArgs: []string{"--authorization-mode=Node,RBAC"},
			failArgs: []string{"--authorization-mode=RBAC"},
		},
		{
			check:    &RBACAuthCheck{},
			passArgs: []string{"--authorization-mode=Node,RBAC"},
			failArgs: []string{"--authorization-mode=Node"},
		},
		{
			check:    &EventRateLimitCheck{},
			passArgs: []string{"--enable-admission-plugins=EventRateLimit,NodeRestriction"},
			failArgs: []string{"--enable-admission-plugins=NodeRestriction"},
		},
		{
			check:    &AlwaysPullImagesCheck{},
			passArgs: []string{"--enable-admission-plugins=AlwaysPullImages"},
			failArgs: []string{"--enable-admission-plugins=NodeRestriction"},
		},
		{
			check:    &SecurityContextAdmissionCheck{},
			passArgs: []string{"--enable-admission-plugins=PodSecurity"},
			failArgs: []string{"--enable-admission-plugins=NodeRestriction"},
		},
		{
			check:    &ServiceAccountAdmissionCheck{},
			passArgs: []string{},
			failArgs: []string{"--disable-admission-plugins=ServiceAccount"},
		},
		{
			check:    &NamespaceLifecycleCheck{},
			passArgs: []string{},
			failArgs: []string{"--disable-admission-plugins=NamespaceLifecycle"},
		},
		{
			check:    &NodeRestrictionCheck{},
			passArgs: []string{"--enable-admission-plugins=NodeRestriction"},
			failArgs: []string{"--enable-admission-plugins=PodSecurity"},
		},
		{
			check:    &APIServerProfilingCheck{},
			passArgs: []string{"--profiling=false"},
			failArgs: []string{"--profiling=true"},
		},
		{
			check:    &AuditLogPathCheck{},
			passArgs: []string{"--audit-log-path=/var/log/audit.log"},
			failArgs: []string{},
		},
		{
			check:    &AuditLogMaxAgeCheck{},
			passArgs: []string{"--audit-log-maxage=30"},
			failArgs: []string{"--audit-log-maxage=10"},
		},
		{
			check:    &AuditLogMaxBackupCheck{},
			passArgs: []string{"--audit-log-maxbackup=10"},
			failArgs: []string{"--audit-log-maxbackup=3"},
		},
		{
			check:    &AuditLogMaxSizeCheck{},
			passArgs: []string{"--audit-log-maxsize=100"},
			failArgs: []string{"--audit-log-maxsize=50"},
		},
		{
			check:    &RequestTimeoutCheck{},
			passArgs: []string{"--request-timeout=60s"},
			failArgs: []string{"--request-timeout=0"},
		},
		{
			check:    &SALookupCheck{},
			passArgs: []string{"--service-account-lookup=true"},
			failArgs: []string{"--service-account-lookup=false"},
		},
		{
			check:    &SAKeyFileCheck{},
			passArgs: []string{"--service-account-key-file=/path/key"},
			failArgs: []string{},
		},
		{
			check:    &EtcdCertCheck{},
			passArgs: []string{"--etcd-certfile=/path/cert", "--etcd-keyfile=/path/key"},
			failArgs: []string{},
		},
		{
			check:    &TLSCertCheck{},
			passArgs: []string{"--tls-cert-file=/path/cert", "--tls-private-key-file=/path/key"},
			failArgs: []string{},
		},
		{
			check:    &ClientCACheck{},
			passArgs: []string{"--client-ca-file=/path/ca"},
			failArgs: []string{},
		},
		{
			check:    &EtcdCACheck{},
			passArgs: []string{"--etcd-cafile=/path/ca"},
			failArgs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.check.ID()+"_Pass", func(t *testing.T) {
			client := fake.NewSimpleClientset(apiServerPod(tt.passArgs...))
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusPass, result.Status, "check %s should pass", tt.check.ID())
		})

		t.Run(tt.check.ID()+"_Fail", func(t *testing.T) {
			client := fake.NewSimpleClientset(apiServerPod(tt.failArgs...))
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusFail, result.Status, "check %s should fail", tt.check.ID())
			assert.NotEmpty(t, result.Evidence, "check %s should have evidence", tt.check.ID())
		})

		t.Run(tt.check.ID()+"_SkipManaged", func(t *testing.T) {
			client := fake.NewSimpleClientset(managedNode())
			result := tt.check.Run(context.Background(), client)
			assert.Equal(t, models.StatusSkip, result.Status, "check %s should skip on managed", tt.check.ID())
		})
	}
}
