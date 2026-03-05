package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestIsManagedCluster_EKS(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-1",
			Labels: map[string]string{"eks.amazonaws.com/nodegroup": "default"},
		},
	})
	assert.True(t, isManagedCluster(context.Background(), client))
}

func TestIsManagedCluster_AKS(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-1",
			Labels: map[string]string{"kubernetes.azure.com/cluster": "test"},
		},
	})
	assert.True(t, isManagedCluster(context.Background(), client))
}

func TestIsManagedCluster_GKE(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-1",
			Labels: map[string]string{"cloud.google.com/gke-nodepool": "default"},
		},
	})
	assert.True(t, isManagedCluster(context.Background(), client))
}

func TestIsManagedCluster_SelfHosted(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-1",
			Labels: map[string]string{"kubernetes.io/os": "linux"},
		},
	})
	assert.False(t, isManagedCluster(context.Background(), client))
}

func TestIsManagedCluster_NoNodes(t *testing.T) {
	client := fake.NewSimpleClientset()
	assert.False(t, isManagedCluster(context.Background(), client))
}

func TestGetControlPlanePod(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kube-apiserver-master",
			Namespace: "kube-system",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "kube-apiserver"}},
		},
	})

	pod, err := getControlPlanePod(context.Background(), client, "kube-apiserver")
	require.NoError(t, err)
	assert.Equal(t, "kube-apiserver-master", pod.Name)
}

func TestGetControlPlanePod_NotFound(t *testing.T) {
	client := fake.NewSimpleClientset()
	_, err := getControlPlanePod(context.Background(), client, "kube-apiserver")
	assert.Error(t, err)
}

func TestGetPodArgs(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "apiserver",
				Command: []string{"kube-apiserver"},
				Args:    []string{"--anonymous-auth=false", "--profiling=false"},
			}},
		},
	}
	args := getPodArgs(pod)
	assert.Equal(t, []string{"kube-apiserver", "--anonymous-auth=false", "--profiling=false"}, args)
}

func TestGetPodArgs_NoContainers(t *testing.T) {
	pod := &corev1.Pod{}
	args := getPodArgs(pod)
	assert.Nil(t, args)
}

func TestGetArgValue(t *testing.T) {
	args := []string{"kube-apiserver", "--anonymous-auth=false", "--profiling=false", "--audit-log-path=/var/log/audit.log"}

	val, ok := getArgValue(args, "--anonymous-auth")
	assert.True(t, ok)
	assert.Equal(t, "false", val)

	val, ok = getArgValue(args, "--audit-log-path")
	assert.True(t, ok)
	assert.Equal(t, "/var/log/audit.log", val)

	_, ok = getArgValue(args, "--missing-flag")
	assert.False(t, ok)
}

func TestHasArg(t *testing.T) {
	args := []string{"kube-apiserver", "--anonymous-auth=false", "--profiling=false"}

	assert.True(t, hasArg(args, "--anonymous-auth"))
	assert.True(t, hasArg(args, "--profiling"))
	assert.False(t, hasArg(args, "--missing"))
}

func TestContainsWildcard(t *testing.T) {
	assert.True(t, containsWildcard([]string{"get", "*"}))
	assert.False(t, containsWildcard([]string{"get", "list"}))
	assert.False(t, containsWildcard(nil))
}

func TestIsSystemNamespace(t *testing.T) {
	assert.True(t, isSystemNamespace("kube-system"))
	assert.True(t, isSystemNamespace("kube-public"))
	assert.True(t, isSystemNamespace("kube-node-lease"))
	assert.False(t, isSystemNamespace("default"))
}

func TestIsSystemRole(t *testing.T) {
	assert.True(t, isSystemRole("system:controller:deployment-controller"))
	assert.False(t, isSystemRole("admin"))
}
