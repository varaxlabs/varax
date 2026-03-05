package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type SysctlsCheck struct{}

func (c *SysctlsCheck) ID() string          { return "CIS-5.2.12" }
func (c *SysctlsCheck) Name() string        { return "Restrict unsafe sysctls" }
func (c *SysctlsCheck) Description() string { return "Ensure pods do not use unsafe sysctls" }
func (c *SysctlsCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *SysctlsCheck) Benchmark() string         { return "CIS" }
func (c *SysctlsCheck) Section() string            { return "5.2.12" }

var safeSysctlPrefixes = []string{
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.ip_unprivileged_port_start",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
}

func (c *SysctlsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	pods, err := scanning.ListPods(ctx, client, "")
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list pods"
		return result
	}

	var evidence []models.Evidence
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.Sysctls != nil {
			for _, sysctl := range pod.Spec.SecurityContext.Sysctls {
				if !isSafeSysctl(sysctl.Name) {
					evidence = append(evidence, models.Evidence{
						Message: fmt.Sprintf("Pod '%s/%s' uses unsafe sysctl '%s'",
							pod.Namespace, pod.Name, sysctl.Name),
						Resource: models.Resource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace},
						Field:    "spec.securityContext.sysctls",
						Value:    sysctl.Name,
					})
				}
			}
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = "No pods using unsafe sysctls"
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d pod(s) with unsafe sysctls", len(evidence))
		result.Evidence = evidence
	}
	return result
}

func isSafeSysctl(name string) bool {
	for _, prefix := range safeSysctlPrefixes {
		if name == prefix || strings.HasPrefix(name, prefix+".") {
			return true
		}
	}
	return false
}

var _ scanning.Check = &SysctlsCheck{}
