package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestHealthProbesCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "healthy-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)},
							},
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(8080)},
							},
						},
					},
				},
			},
		},
	)

	result := (&HealthProbesCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestHealthProbesCheck_Fail_NoProbes(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "no-probes-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app"},
				},
			},
		},
	)

	result := (&HealthProbesCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Contains(t, result.Evidence[0].Value, "livenessProbe")
	assert.Contains(t, result.Evidence[0].Value, "readinessProbe")
}

func TestHealthProbesCheck_Fail_MissingReadiness(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "partial-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "app",
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)},
							},
						},
					},
				},
			},
		},
	)

	result := (&HealthProbesCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Contains(t, result.Evidence[0].Value, "readinessProbe")
}

func TestHealthProbesCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "system-pod", Namespace: "kube-system"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "proxy"},
				},
			},
		},
	)

	result := (&HealthProbesCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
