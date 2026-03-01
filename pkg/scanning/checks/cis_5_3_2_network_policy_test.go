package checks

import (
	"context"
	"testing"

	"github.com/kubeshield/operator/pkg/models"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNetworkPolicyCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "default"},
		},
	)

	check := &NetworkPolicyCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNetworkPolicyCheck_FailNoPolicy(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
	)

	check := &NetworkPolicyCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestNetworkPolicyCheck_SkipsSystemNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-public"}},
	)

	check := &NetworkPolicyCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNetworkPolicyCheck_MultipleNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app-a"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app-b"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "app-a"},
		},
		// app-b has no policy
	)

	check := &NetworkPolicyCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Contains(t, result.Evidence[0].Message, "app-b")
}
