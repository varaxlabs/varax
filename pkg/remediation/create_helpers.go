package remediation

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// networkingv1Policy is a JSON-serializable representation for creating NetworkPolicies.
type networkingv1Policy struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (p *networkingv1Policy) toNetworkPolicy() *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.Name,
			Namespace: p.Namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

// corev1LimitRange is a JSON-serializable representation for creating LimitRanges.
type corev1LimitRange struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (l *corev1LimitRange) toLimitRange() *corev1.LimitRange {
	return &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      l.Name,
			Namespace: l.Namespace,
		},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{
				{
					Type: corev1.LimitTypeContainer,
					Default: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
					DefaultRequest: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
				},
			},
		},
	}
}
