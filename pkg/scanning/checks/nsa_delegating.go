package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// nsaDelegatingCheck wraps a CIS check and re-labels the result with NSA metadata.
type nsaDelegatingCheck struct {
	id          string
	name        string
	description string
	severity    models.Severity
	section     string
	delegate    scanning.Check
}

func (c *nsaDelegatingCheck) ID() string                { return c.id }
func (c *nsaDelegatingCheck) Name() string              { return c.name }
func (c *nsaDelegatingCheck) Description() string       { return c.description }
func (c *nsaDelegatingCheck) Severity() models.Severity { return c.severity }
func (c *nsaDelegatingCheck) Benchmark() string         { return "NSA-CISA" }
func (c *nsaDelegatingCheck) Section() string           { return c.section }

func (c *nsaDelegatingCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := c.delegate.Run(ctx, client)
	// Re-wrap with NSA metadata
	result.ID = c.id
	result.Name = c.name
	result.Description = c.description
	result.Benchmark = "NSA-CISA"
	result.Section = c.section
	result.Severity = c.severity
	return result
}

var (
	NSAPS1 = &nsaDelegatingCheck{id: "NSA-PS-1", name: "Run containers as non-root", description: "Ensure containers run as non-root users", severity: models.SeverityHigh, section: "PS-1", delegate: &RootContainerCheck{}}
	NSAPS2 = &nsaDelegatingCheck{id: "NSA-PS-2", name: "Drop all capabilities", description: "Ensure containers drop all capabilities", severity: models.SeverityHigh, section: "PS-2", delegate: &DropCapabilitiesCheck{}}
	NSAPS3 = &nsaDelegatingCheck{id: "NSA-PS-3", name: "No privileged containers", description: "Ensure containers do not run privileged", severity: models.SeverityCritical, section: "PS-3", delegate: &PrivilegedContainerCheck{}}
	NSAPS4 = &nsaDelegatingCheck{id: "NSA-PS-4", name: "No privilege escalation", description: "Ensure containers do not allow privilege escalation", severity: models.SeverityHigh, section: "PS-4", delegate: &PrivilegeEscalationCheck{}}
	NSAPS5 = &nsaDelegatingCheck{id: "NSA-PS-5", name: "No hostPID sharing", description: "Ensure pods do not share host PID namespace", severity: models.SeverityHigh, section: "PS-5", delegate: &HostPIDCheck{}}
	NSAPS6 = &nsaDelegatingCheck{id: "NSA-PS-6", name: "No hostNetwork sharing", description: "Ensure pods do not share host network", severity: models.SeverityHigh, section: "PS-6", delegate: &HostNetworkCheck{}}
	NSANS1 = &nsaDelegatingCheck{id: "NSA-NS-1", name: "NetworkPolicy per namespace", description: "Ensure NetworkPolicy exists in every namespace", severity: models.SeverityHigh, section: "NS-1", delegate: &NetworkPolicyCheck{}}
	NSAAA1 = &nsaDelegatingCheck{id: "NSA-AA-1", name: "Restrict cluster-admin usage", description: "Limit cluster-admin role binding", severity: models.SeverityCritical, section: "AA-1", delegate: &ClusterAdminCheck{}}
	NSAAA2 = &nsaDelegatingCheck{id: "NSA-AA-2", name: "No wildcard RBAC", description: "No wildcard permissions in RBAC roles", severity: models.SeverityHigh, section: "AA-2", delegate: &WildcardRBACCheck{}}
	NSAAA3 = &nsaDelegatingCheck{id: "NSA-AA-3", name: "Minimize default SA usage", description: "Minimize default service account usage", severity: models.SeverityMedium, section: "AA-3", delegate: &DefaultServiceAccountCheck{}}
	NSAAA4 = &nsaDelegatingCheck{id: "NSA-AA-4", name: "SA token auto-mount disabled", description: "Disable automatic SA token mounting", severity: models.SeverityMedium, section: "AA-4", delegate: &SATokenAutoMountCheck{}}
	NSALM1 = &nsaDelegatingCheck{id: "NSA-LM-1", name: "Audit log path set", description: "Ensure audit logging path is configured", severity: models.SeverityHigh, section: "LM-1", delegate: &AuditLogPathCheck{}}
	NSALM2 = &nsaDelegatingCheck{id: "NSA-LM-2", name: "Audit log retention", description: "Ensure audit log retention is adequate", severity: models.SeverityMedium, section: "LM-2", delegate: &AuditLogMaxAgeCheck{}}
	NSASC1 = &nsaDelegatingCheck{id: "NSA-SC-1", name: "Security context set", description: "Ensure all pods have security context", severity: models.SeverityHigh, section: "SC-1", delegate: &SecurityContextCheck{}}
	NSASC2 = &nsaDelegatingCheck{id: "NSA-SC-2", name: "Seccomp profile set", description: "Ensure pods use seccomp profiles", severity: models.SeverityMedium, section: "SC-2", delegate: &SeccompCheck{}}
)

var _ scanning.Check = &nsaDelegatingCheck{}
