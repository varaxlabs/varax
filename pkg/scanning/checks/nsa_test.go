package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNSADelegatingChecks(t *testing.T) {
	// All delegating checks should produce NSA-CISA benchmark results
	checks := []scanning.Check{NSAPS1, NSAPS2, NSAPS3, NSAPS4, NSAPS5, NSAPS6, NSANS1, NSAAA1, NSAAA2, NSAAA3, NSAAA4, NSASC1, NSASC2}
	client := fake.NewSimpleClientset()
	for _, chk := range checks {
		t.Run(chk.ID(), func(t *testing.T) {
			result := chk.Run(context.Background(), client)
			assert.Equal(t, "NSA-CISA", result.Benchmark)
			assert.Equal(t, chk.ID(), result.ID)
		})
	}
}

func TestNSAImmutableFS_Pass(t *testing.T) {
	readOnly := true
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "safe", Namespace: "app"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", SecurityContext: &corev1.SecurityContext{ReadOnlyRootFilesystem: &readOnly},
		}}},
	})
	result := (&NSAImmutableFSCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSAImmutableFS_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "app"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	})
	result := (&NSAImmutableFSCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestNSAResourceLimits_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "limited", Namespace: "app"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app",
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
			},
		}}},
	})
	result := (&NSAResourceLimitsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSAResourceLimits_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "unlimited", Namespace: "app"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	})
	result := (&NSAResourceLimitsCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestNSAAnonAuth_Pass(t *testing.T) {
	client := fake.NewSimpleClientset()
	result := (&NSAAnonAuthCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSAImagePullPolicy_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "always", Namespace: "app"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", ImagePullPolicy: corev1.PullAlways,
		}}},
	})
	result := (&NSAImagePullPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSAImagePullPolicy_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "never", Namespace: "app"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", ImagePullPolicy: corev1.PullIfNotPresent,
		}}},
	})
	result := (&NSAImagePullPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}
