package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/rbac"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type RBACOverpermissiveCheck struct{}

func (c *RBACOverpermissiveCheck) ID() string          { return "RBAC-1" }
func (c *RBACOverpermissiveCheck) Name() string        { return "Roles with wildcard access" }
func (c *RBACOverpermissiveCheck) Description() string { return "Detect roles with overpermissive wildcard access" }
func (c *RBACOverpermissiveCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *RBACOverpermissiveCheck) Benchmark() string         { return "RBAC" }
func (c *RBACOverpermissiveCheck) Section() string            { return "1" }

func (c *RBACOverpermissiveCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	clusterRoles, err := scanning.ListClusterRoles(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list ClusterRoles"
		return result
	}
	roles, err := scanning.ListRoles(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list Roles"
		return result
	}

	findings := rbac.AnalyzeOverPermissiveRoles(clusterRoles, roles)
	return findingsToResult(result, findings, "roles with wildcard access")
}

type RBACEscalationCheck struct{}

func (c *RBACEscalationCheck) ID() string          { return "RBAC-2" }
func (c *RBACEscalationCheck) Name() string        { return "Roles that can create bindings" }
func (c *RBACEscalationCheck) Description() string { return "Detect roles that can create or escalate RBAC bindings" }
func (c *RBACEscalationCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *RBACEscalationCheck) Benchmark() string         { return "RBAC" }
func (c *RBACEscalationCheck) Section() string            { return "2" }

func (c *RBACEscalationCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	clusterRoles, err := scanning.ListClusterRoles(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list ClusterRoles"
		return result
	}
	bindings, err := scanning.ListClusterRoleBindings(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list ClusterRoleBindings"
		return result
	}

	findings := rbac.AnalyzeEscalationPaths(clusterRoles, bindings)
	return findingsToResult(result, findings, "roles with escalation paths")
}

type RBACSAPrivilegesCheck struct{}

func (c *RBACSAPrivilegesCheck) ID() string          { return "RBAC-3" }
func (c *RBACSAPrivilegesCheck) Name() string        { return "SAs with cluster-admin-equivalent access" }
func (c *RBACSAPrivilegesCheck) Description() string { return "Detect service accounts with excessive privileges" }
func (c *RBACSAPrivilegesCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *RBACSAPrivilegesCheck) Benchmark() string         { return "RBAC" }
func (c *RBACSAPrivilegesCheck) Section() string            { return "3" }

func (c *RBACSAPrivilegesCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	sas, err := scanning.ListServiceAccounts(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list ServiceAccounts"
		return result
	}
	bindings, err := scanning.ListClusterRoleBindings(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list ClusterRoleBindings"
		return result
	}

	findings := rbac.AnalyzeSAPrivileges(sas, bindings)
	return findingsToResult(result, findings, "service accounts with cluster-admin access")
}

type RBACNamespaceScopeCheck struct{}

func (c *RBACNamespaceScopeCheck) ID() string          { return "RBAC-4" }
func (c *RBACNamespaceScopeCheck) Name() string        { return "Least-privilege namespace scope" }
func (c *RBACNamespaceScopeCheck) Description() string { return "Detect RoleBindings that reference ClusterRoles unnecessarily" }
func (c *RBACNamespaceScopeCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *RBACNamespaceScopeCheck) Benchmark() string         { return "RBAC" }
func (c *RBACNamespaceScopeCheck) Section() string            { return "4" }

func (c *RBACNamespaceScopeCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	result := baseResult(c)

	roles, err := scanning.ListRoles(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list Roles"
		return result
	}
	rbs, err := scanning.ListRoleBindings(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list RoleBindings"
		return result
	}

	findings := rbac.AnalyzeNamespaceScope(roles, rbs)
	return findingsToResult(result, findings, "bindings referencing ClusterRoles")
}

func findingsToResult(result models.CheckResult, findings []rbac.Finding, description string) models.CheckResult {
	if len(findings) == 0 {
		result.Status = models.StatusPass
		result.Message = fmt.Sprintf("No %s found", description)
		return result
	}

	var evidence []models.Evidence
	for _, f := range findings {
		evidence = append(evidence, models.Evidence{
			Message:  f.Description,
			Resource: models.Resource{Kind: "RBAC", Name: f.Resource, Namespace: f.Namespace},
		})
	}
	result.Status = models.StatusFail
	result.Message = fmt.Sprintf("Found %d %s", len(findings), description)
	result.Evidence = evidence
	return result
}

var (
	_ scanning.Check = &RBACOverpermissiveCheck{}
	_ scanning.Check = &RBACEscalationCheck{}
	_ scanning.Check = &RBACSAPrivilegesCheck{}
	_ scanning.Check = &RBACNamespaceScopeCheck{}
)
