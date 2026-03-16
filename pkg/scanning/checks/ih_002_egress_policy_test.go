package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEgressPolicyCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-egress", Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		},
	)

	result := (&EgressPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestEgressPolicyCheck_Fail_NoEgressPolicy(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
	)

	result := (&EgressPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Contains(t, result.Evidence[0].Message, "default")
}

func TestEgressPolicyCheck_Fail_IngressOnlyPolicy(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "ingress-only", Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		},
	)

	result := (&EgressPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
}

func TestEgressPolicyCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	)

	result := (&EgressPolicyCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
