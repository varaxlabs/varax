package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/varax/operator/pkg/models"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTLSIngressCheck_Pass(t *testing.T) {
	client := fake.NewSimpleClientset(
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "secure-ingress", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"example.com"}, SecretName: "tls-secret"},
				},
			},
		},
	)

	result := (&TLSIngressCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestTLSIngressCheck_Pass_NoIngresses(t *testing.T) {
	client := fake.NewSimpleClientset()
	result := (&TLSIngressCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}

func TestTLSIngressCheck_Fail_NoTLS(t *testing.T) {
	client := fake.NewSimpleClientset(
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "insecure-ingress", Namespace: "default"},
			Spec:       networkingv1.IngressSpec{},
		},
	)

	result := (&TLSIngressCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusFail, result.Status)
	assert.Len(t, result.Evidence, 1)
	assert.Contains(t, result.Evidence[0].Message, "plaintext HTTP")
}

func TestTLSIngressCheck_SkipsSystemNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "system-ingress", Namespace: "kube-system"},
			Spec:       networkingv1.IngressSpec{},
		},
	)

	result := (&TLSIngressCheck{}).Run(context.Background(), client)
	assert.Equal(t, models.StatusPass, result.Status)
}
