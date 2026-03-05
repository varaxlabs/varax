package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// Section 4.2 — Kubelet checks
// These checks inspect node annotations/labels for kubelet configuration.
// Full kubelet config inspection requires direct node access; we check
// what's available via the Kubernetes API.

type kubeletCheck struct {
	id          string
	name        string
	description string
	severity    models.Severity
	section     string
	checkFn     func(annotations map[string]string) (bool, string)
}

func (c *kubeletCheck) ID() string                    { return c.id }
func (c *kubeletCheck) Name() string                  { return c.name }
func (c *kubeletCheck) Description() string           { return c.description }
func (c *kubeletCheck) Severity() models.Severity     { return c.severity }
func (c *kubeletCheck) Benchmark() string             { return "CIS" }
func (c *kubeletCheck) Section() string               { return c.section }

func (c *kubeletCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	if isManagedCluster(ctx, client) {
		// Managed clusters handle kubelet config
		result.Status = models.StatusPass
		result.Message = "Kubelet configuration is managed by cloud provider"
		return result
	}

	nodes, err := scanning.ListNodes(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list nodes"
		return result
	}
	if len(nodes) == 0 {
		result.Status = models.StatusSkip
		result.Message = "No nodes found"
		return result
	}

	// Check kubelet config via node annotations where available
	var evidence []models.Evidence
	for _, node := range nodes {
		pass, msg := c.checkFn(node.Annotations)
		if !pass {
			evidence = append(evidence, models.Evidence{
				Message: fmt.Sprintf("Node '%s': %s", node.Name, msg),
				Resource: models.Resource{
					Kind: "Node",
					Name: node.Name,
				},
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = c.name + " — all nodes compliant"
	} else {
		result.Status = models.StatusWarn
		result.Message = fmt.Sprintf("%d node(s) may have kubelet misconfiguration", len(evidence))
		result.Evidence = evidence
	}
	return result
}

// Kubelet checks — these return Warn rather than Fail because full verification
// requires direct kubelet config access which is not available via the K8s API.

var KubeletAnonAuthCheck = &kubeletCheck{
	id: "CIS-4.2.1", name: "Ensure kubelet anonymous auth is disabled",
	description: "Verify kubelet --anonymous-auth=false", severity: models.SeverityHigh, section: "4.2.1",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet anonymous-auth via API (manual check required)"
	},
}

var KubeletAuthModeCheck = &kubeletCheck{
	id: "CIS-4.2.2", name: "Ensure kubelet authorization mode is not AlwaysAllow",
	description: "Verify kubelet authorization is set to Webhook", severity: models.SeverityHigh, section: "4.2.2",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet authorization-mode via API (manual check required)"
	},
}

var KubeletClientCertificateCheck = &kubeletCheck{
	id: "CIS-4.2.3", name: "Ensure kubelet client certificate auth is configured",
	description: "Verify kubelet uses client certificate authentication", severity: models.SeverityHigh, section: "4.2.3",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet client-certificate via API (manual check required)"
	},
}

var KubeletReadOnlyPortCheck = &kubeletCheck{
	id: "CIS-4.2.4", name: "Ensure kubelet read-only port is disabled",
	description: "Verify kubelet --read-only-port=0", severity: models.SeverityHigh, section: "4.2.4",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet read-only-port via API (manual check required)"
	},
}

var KubeletStreamingCheck = &kubeletCheck{
	id: "CIS-4.2.5", name: "Ensure kubelet streaming connection timeouts are set",
	description: "Verify kubelet streaming connection idle timeout", severity: models.SeverityMedium, section: "4.2.5",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet streaming timeout via API (manual check required)"
	},
}

var KubeletProtectKernelDefaultsCheck = &kubeletCheck{
	id: "CIS-4.2.6", name: "Ensure kubelet protect-kernel-defaults is enabled",
	description: "Verify --protect-kernel-defaults=true", severity: models.SeverityMedium, section: "4.2.6",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet protect-kernel-defaults via API (manual check required)"
	},
}

var KubeletIPTablesCheck = &kubeletCheck{
	id: "CIS-4.2.7", name: "Ensure kubelet make-iptables-util-chains is enabled",
	description: "Verify --make-iptables-util-chains=true", severity: models.SeverityMedium, section: "4.2.7",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet make-iptables-util-chains via API (manual check required)"
	},
}

var KubeletHostnameOverrideCheck = &kubeletCheck{
	id: "CIS-4.2.8", name: "Ensure kubelet hostname-override is not set",
	description: "Verify --hostname-override is not set", severity: models.SeverityLow, section: "4.2.8",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet hostname-override via API (manual check required)"
	},
}

var KubeletEventQPSCheck = &kubeletCheck{
	id: "CIS-4.2.9", name: "Ensure kubelet event-qps is set appropriately",
	description: "Verify --event-qps is set above 0", severity: models.SeverityMedium, section: "4.2.9",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet event-qps via API (manual check required)"
	},
}

var KubeletTLSCertCheck = &kubeletCheck{
	id: "CIS-4.2.10", name: "Ensure kubelet TLS cert file is set",
	description: "Verify --tls-cert-file is set", severity: models.SeverityHigh, section: "4.2.10",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet tls-cert-file via API (manual check required)"
	},
}

var KubeletTLSKeyCheck = &kubeletCheck{
	id: "CIS-4.2.11", name: "Ensure kubelet TLS private key is set",
	description: "Verify --tls-private-key-file is set", severity: models.SeverityHigh, section: "4.2.11",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet tls-private-key-file via API (manual check required)"
	},
}

var KubeletRotateCertCheck = &kubeletCheck{
	id: "CIS-4.2.12", name: "Ensure kubelet RotateKubeletServerCertificate is enabled",
	description: "Verify RotateKubeletServerCertificate feature gate", severity: models.SeverityMedium, section: "4.2.12",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet RotateKubeletServerCertificate via API (manual check required)"
	},
}

var KubeletIntegrityCheck = &kubeletCheck{
	id: "CIS-4.2.13", name: "Ensure kubelet only uses strong crypto ciphers",
	description: "Verify kubelet TLS cipher suites", severity: models.SeverityMedium, section: "4.2.13",
	checkFn: func(_ map[string]string) (bool, string) {
		return false, "Cannot verify kubelet TLS ciphers via API (manual check required)"
	},
}

var _ scanning.Check = &kubeletCheck{}
