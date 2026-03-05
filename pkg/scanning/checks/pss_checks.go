package checks

import (
	"context"
	"fmt"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// PSS checks verify Pod Security Standards namespace labels.

type PSSEnforceLabelCheck struct{}

func (c *PSSEnforceLabelCheck) ID() string          { return "PSS-1.1" }
func (c *PSSEnforceLabelCheck) Name() string        { return "Ensure pod-security enforce label is set" }
func (c *PSSEnforceLabelCheck) Description() string { return "Non-system namespaces should have pod-security.kubernetes.io/enforce label" }
func (c *PSSEnforceLabelCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *PSSEnforceLabelCheck) Benchmark() string         { return "PSS" }
func (c *PSSEnforceLabelCheck) Section() string            { return "1.1" }

func (c *PSSEnforceLabelCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return checkPSSLabel(ctx, client, c, "pod-security.kubernetes.io/enforce", "")
}

type PSSBaselineEnforceCheck struct{}

func (c *PSSBaselineEnforceCheck) ID() string          { return "PSS-1.2" }
func (c *PSSBaselineEnforceCheck) Name() string        { return "Ensure enforce level is at least baseline" }
func (c *PSSBaselineEnforceCheck) Description() string { return "Enforce label should be baseline or restricted" }
func (c *PSSBaselineEnforceCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *PSSBaselineEnforceCheck) Benchmark() string         { return "PSS" }
func (c *PSSBaselineEnforceCheck) Section() string            { return "1.2" }

func (c *PSSBaselineEnforceCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return checkPSSLabel(ctx, client, c, "pod-security.kubernetes.io/enforce", "baseline")
}

type PSSRestrictedEnforceCheck struct{}

func (c *PSSRestrictedEnforceCheck) ID() string          { return "PSS-1.3" }
func (c *PSSRestrictedEnforceCheck) Name() string        { return "Ensure enforce level is restricted where appropriate" }
func (c *PSSRestrictedEnforceCheck) Description() string { return "Enforce label should be restricted for sensitive namespaces" }
func (c *PSSRestrictedEnforceCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *PSSRestrictedEnforceCheck) Benchmark() string         { return "PSS" }
func (c *PSSRestrictedEnforceCheck) Section() string            { return "1.3" }

func (c *PSSRestrictedEnforceCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return checkPSSLabel(ctx, client, c, "pod-security.kubernetes.io/enforce", "restricted")
}

type PSSAuditLabelCheck struct{}

func (c *PSSAuditLabelCheck) ID() string          { return "PSS-2.1" }
func (c *PSSAuditLabelCheck) Name() string        { return "Ensure pod-security audit label is set" }
func (c *PSSAuditLabelCheck) Description() string { return "Non-system namespaces should have pod-security.kubernetes.io/audit label" }
func (c *PSSAuditLabelCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *PSSAuditLabelCheck) Benchmark() string         { return "PSS" }
func (c *PSSAuditLabelCheck) Section() string            { return "2.1" }

func (c *PSSAuditLabelCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return checkPSSLabel(ctx, client, c, "pod-security.kubernetes.io/audit", "")
}

type PSSWarnLabelCheck struct{}

func (c *PSSWarnLabelCheck) ID() string          { return "PSS-2.2" }
func (c *PSSWarnLabelCheck) Name() string        { return "Ensure pod-security warn label is set" }
func (c *PSSWarnLabelCheck) Description() string { return "Non-system namespaces should have pod-security.kubernetes.io/warn label" }
func (c *PSSWarnLabelCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *PSSWarnLabelCheck) Benchmark() string         { return "PSS" }
func (c *PSSWarnLabelCheck) Section() string            { return "2.2" }

func (c *PSSWarnLabelCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return checkPSSLabel(ctx, client, c, "pod-security.kubernetes.io/warn", "")
}

// checkPSSLabel checks a pod-security label across namespaces.
// If minLevel is empty, just checks the label exists.
// If minLevel is set, checks the label value meets minimum level.
func checkPSSLabel(ctx context.Context, client kubernetes.Interface, c scanning.Check, label, minLevel string) models.CheckResult {
	result := baseResult(c)

	namespaces, err := scanning.ListNamespaces(ctx, client)
	if err != nil {
		result.Status = models.StatusSkip
		result.Message = "Failed to list namespaces"
		return result
	}

	var evidence []models.Evidence
	for _, ns := range namespaces {
		if isSystemNamespace(ns.Name) || ns.Name == "default" {
			continue
		}

		val, ok := ns.Labels[label]
		if !ok {
			evidence = append(evidence, models.Evidence{
				Message:  fmt.Sprintf("Namespace '%s' missing %s label", ns.Name, label),
				Resource: models.Resource{Kind: "Namespace", Name: ns.Name},
				Field:    "metadata.labels",
			})
		} else if minLevel != "" && !meetsMinPSSLevel(val, minLevel) {
			evidence = append(evidence, models.Evidence{
				Message:  fmt.Sprintf("Namespace '%s' has %s=%s (minimum: %s)", ns.Name, label, val, minLevel),
				Resource: models.Resource{Kind: "Namespace", Name: ns.Name},
				Field:    "metadata.labels",
				Value:    val,
			})
		}
	}

	if len(evidence) == 0 {
		result.Status = models.StatusPass
		result.Message = fmt.Sprintf("All namespaces have appropriate %s label", label)
	} else {
		result.Status = models.StatusFail
		result.Message = fmt.Sprintf("Found %d namespace(s) with missing or insufficient %s", len(evidence), label)
		result.Evidence = evidence
	}
	return result
}

// meetsMinPSSLevel checks if value meets minimum PSS level.
// Order: privileged < baseline < restricted
func meetsMinPSSLevel(value, minimum string) bool {
	levels := map[string]int{"privileged": 0, "baseline": 1, "restricted": 2}
	vLevel, vOk := levels[value]
	mLevel, mOk := levels[minimum]
	if !vOk || !mOk {
		return false
	}
	return vLevel >= mLevel
}

var (
	_ scanning.Check = &PSSEnforceLabelCheck{}
	_ scanning.Check = &PSSBaselineEnforceCheck{}
	_ scanning.Check = &PSSRestrictedEnforceCheck{}
	_ scanning.Check = &PSSAuditLabelCheck{}
	_ scanning.Check = &PSSWarnLabelCheck{}
)
