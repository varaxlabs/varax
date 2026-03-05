package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAnonAuthCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(apiServerPod("--anonymous-auth=false"))
	result := (&AnonAuthCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestAnonAuthCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(apiServerPod("--anonymous-auth=true"))
	result := (&AnonAuthCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestAnonAuthCheck_SkipManaged(t *testing.T) {
	client := fake.NewSimpleClientset(managedNode())
	result := (&AnonAuthCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusSkip, result.Status)
}

// Test helpers for API server checks
func apiServerPod(args ...string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-master", Namespace: "kube-system"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "kube-apiserver",
				Command: []string{"kube-apiserver"},
				Args:    args,
			}},
		},
	}
}

func managedNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "managed-node",
			Labels: map[string]string{"eks.amazonaws.com/nodegroup": "default"},
		},
	}
}
