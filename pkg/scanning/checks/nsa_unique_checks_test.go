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

// --- NSADefaultDenyIngressCheck (NSA-NS-2) ---

func TestNSADefaultDenyIngressCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all-ingress", Namespace: "production"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{},
			},
		},
	)

	check := &NSADefaultDenyIngressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSADefaultDenyIngressCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
	)

	check := &NSADefaultDenyIngressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestNSADefaultDenyIngressCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system"},
		},
	)

	check := &NSADefaultDenyIngressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSADefaultDenyIngressCheck_SkipsDefaultNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		},
	)

	check := &NSADefaultDenyIngressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSADefaultDenyIngressCheck_NonEmptyPodSelectorNotCounted(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "selective-ingress", Namespace: "production"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{},
			},
		},
	)

	check := &NSADefaultDenyIngressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status, "policy with non-empty PodSelector should not count as default deny")
}

// --- NSADefaultDenyEgressCheck (NSA-NS-3) ---

func TestNSADefaultDenyEgressCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-all-egress", Namespace: "production"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress:      []networkingv1.NetworkPolicyEgressRule{},
			},
		},
	)

	check := &NSADefaultDenyEgressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSADefaultDenyEgressCheck_Fail(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
	)

	check := &NSADefaultDenyEgressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
}

func TestNSADefaultDenyEgressCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-system"},
		},
	)

	check := &NSADefaultDenyEgressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSADefaultDenyEgressCheck_SkipsDefaultNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		},
	)

	check := &NSADefaultDenyEgressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusPass, result.Status)
}

func TestNSADefaultDenyEgressCheck_NonEmptyPodSelectorNotCounted(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "selective-egress", Namespace: "production"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "web"},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress:      []networkingv1.NetworkPolicyEgressRule{},
			},
		},
	)

	check := &NSADefaultDenyEgressCheck{}
	result := check.Run(context.Background(), client)

	assert.Equal(t, models.StatusFail, result.Status, "policy with non-empty PodSelector should not count as default deny")
}
