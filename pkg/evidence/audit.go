package evidence

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type auditSnapshot struct {
	APIServerFound  bool   `json:"apiServerFound"`
	AuditLogPath    string `json:"auditLogPath,omitempty"`
	AuditPolicyFile string `json:"auditPolicyFile,omitempty"`
	AuditMaxAge     string `json:"auditMaxAge,omitempty"`
}

func collectAudit(ctx context.Context, client kubernetes.Interface) ([]EvidenceItem, error) {
	now := time.Now().UTC()
	snap := auditSnapshot{}

	pods, err := client.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, "kube-apiserver") {
			snap.APIServerFound = true
			if len(pod.Spec.Containers) > 0 {
				for _, arg := range pod.Spec.Containers[0].Args {
					if strings.HasPrefix(arg, "--audit-log-path=") {
						snap.AuditLogPath = strings.TrimPrefix(arg, "--audit-log-path=")
					}
					if strings.HasPrefix(arg, "--audit-policy-file=") {
						snap.AuditPolicyFile = strings.TrimPrefix(arg, "--audit-policy-file=")
					}
					if strings.HasPrefix(arg, "--audit-log-maxage=") {
						snap.AuditMaxAge = strings.TrimPrefix(arg, "--audit-log-maxage=")
					}
				}
			}
			break
		}
	}

	desc := "Audit logging configuration"
	if !snap.APIServerFound {
		desc = "Audit logging: API server not found (managed cluster)"
	} else if snap.AuditLogPath != "" {
		desc = fmt.Sprintf("Audit logging configured: path=%s", snap.AuditLogPath)
	}

	return []EvidenceItem{{
		Category:    "Audit",
		Description: desc,
		Data:        snap,
		Timestamp:   now,
	}}, nil
}
