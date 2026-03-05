package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// --- SystemMastersCheck (CIS-5.1.7) ---

func TestSystemMastersCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-binding"},
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "developers"},
			},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
		},
	)

	check := &SystemMastersCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestSystemMastersCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "custom-admin-binding"},
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "system:masters"},
			},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		},
	)

	check := &SystemMastersCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestSystemMastersCheck_SkipsSystemRoles(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "system:masters"},
			},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:discovery"},
		},
	)

	check := &SystemMastersCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

// --- ProcMountCheck (CIS-5.2.9) ---

func TestProcMountCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", SecurityContext: &corev1.SecurityContext{}},
				},
			},
		},
	)

	check := &ProcMountCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestProcMountCheck_Fail(t *testing.T) {
	unmasked := corev1.UnmaskedProcMount
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							ProcMount: &unmasked,
						},
					},
				},
			},
		},
	)

	check := &ProcMountCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestProcMountCheck_SkipsSystemNamespace(t *testing.T) {
	unmasked := corev1.UnmaskedProcMount
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							ProcMount: &unmasked,
						},
					},
				},
			},
		},
	)

	check := &ProcMountCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

// --- HostProcessCheck (CIS-5.2.10) ---

func TestHostProcessCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", SecurityContext: &corev1.SecurityContext{}},
				},
			},
		},
	)

	check := &HostProcessCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestHostProcessCheck_Fail(t *testing.T) {
	hostProcess := true
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							WindowsOptions: &corev1.WindowsSecurityContextOptions{
								HostProcess: &hostProcess,
							},
						},
					},
				},
			},
		},
	)

	check := &HostProcessCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestHostProcessCheck_SkipsSystemNamespace(t *testing.T) {
	hostProcess := true
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							WindowsOptions: &corev1.WindowsSecurityContextOptions{
								HostProcess: &hostProcess,
							},
						},
					},
				},
			},
		},
	)

	check := &HostProcessCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

// --- AppArmorCheck (CIS-5.2.11) ---

func TestAppArmorCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "safe-pod",
				Namespace: "default",
				Annotations: map[string]string{
					"container.apparmor.security.beta.kubernetes.io/app": "runtime/default",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	check := &AppArmorCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestAppArmorCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bad-pod",
				Namespace: "default",
				Annotations: map[string]string{
					"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	check := &AppArmorCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestAppArmorCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "system-pod",
				Namespace: "kube-system",
				Annotations: map[string]string{
					"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	check := &AppArmorCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestAppArmorCheck_NoAnnotation(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "simple-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	check := &AppArmorCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

// --- SysctlsCheck (CIS-5.2.12) ---

func TestSysctlsCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{
						{Name: "net.ipv4.ip_local_port_range", Value: "1024 65535"},
					},
				},
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	check := &SysctlsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestSysctlsCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{
						{Name: "kernel.msgmax", Value: "65536"},
					},
				},
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	check := &SysctlsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestSysctlsCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
			Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{
						{Name: "kernel.msgmax", Value: "65536"},
					},
				},
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	check := &SysctlsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestSysctlsCheck_NoSysctls(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "simple-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	check := &SysctlsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

// --- NamespaceLimitsCheck (CIS-5.7.1) ---

func TestNamespaceLimitsCheck_Pass_WithLimitRange(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
		&corev1.LimitRange{
			ObjectMeta: metav1.ObjectMeta{Name: "default-limits", Namespace: "production"},
		},
	)

	check := &NamespaceLimitsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNamespaceLimitsCheck_Pass_WithResourceQuota(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
		&corev1.ResourceQuota{
			ObjectMeta: metav1.ObjectMeta{Name: "default-quota", Namespace: "production"},
		},
	)

	check := &NamespaceLimitsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNamespaceLimitsCheck_Warn(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
	)

	check := &NamespaceLimitsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusWarn, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestNamespaceLimitsCheck_SkipsSystemNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system"},
		},
	)

	check := &NamespaceLimitsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNamespaceLimitsCheck_SkipsDefaultNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		},
	)

	check := &NamespaceLimitsCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

// --- CNINetworkPolicyCheck (CIS-5.3.1) ---

func TestCNINetworkPolicyCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset()

	check := &CNINetworkPolicyCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}
