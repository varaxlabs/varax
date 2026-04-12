package evidence

import (
	"context"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// EncryptionSnapshot contains TLS and encryption configuration from etcd and the API server.
type EncryptionSnapshot struct {
	EtcdFound       bool   `json:"etcdFound"`
	CertFileSet     bool   `json:"certFileSet"`
	ClientCertAuth  bool   `json:"clientCertAuth"`
	PeerCertFileSet bool   `json:"peerCertFileSet"`
	TrustedCASet    bool   `json:"trustedCASet"`
	TLSCertFile     string `json:"tlsCertFile,omitempty"`
}

func collectEncryption(ctx context.Context, client kubernetes.Interface) ([]EvidenceItem, error) {
	now := time.Now().UTC()
	snap := EncryptionSnapshot{}

	pods, err := client.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, "etcd") {
			snap.EtcdFound = true
			if len(pod.Spec.Containers) > 0 {
				for _, arg := range pod.Spec.Containers[0].Args {
					switch {
					case strings.HasPrefix(arg, "--cert-file="):
						snap.CertFileSet = true
					case strings.HasPrefix(arg, "--client-cert-auth=true"):
						snap.ClientCertAuth = true
					case strings.HasPrefix(arg, "--peer-cert-file="):
						snap.PeerCertFileSet = true
					case strings.HasPrefix(arg, "--trusted-ca-file="):
						snap.TrustedCASet = true
					}
				}
			}
			break
		}

		if strings.HasPrefix(pod.Name, "kube-apiserver") && len(pod.Spec.Containers) > 0 {
			for _, arg := range pod.Spec.Containers[0].Args {
				if strings.HasPrefix(arg, "--tls-cert-file=") {
					snap.TLSCertFile = strings.TrimPrefix(arg, "--tls-cert-file=")
				}
			}
		}
	}

	desc := "Encryption/TLS configuration snapshot"
	if !snap.EtcdFound {
		desc = "Encryption: etcd not found (managed cluster)"
	}

	return []EvidenceItem{{
		Category:    "Encryption",
		Type:        "encryption-tls",
		Description: desc,
		Data:        snap,
		Timestamp:   now,
		SHA256:      computeSHA256(snap),
	}}, nil
}
