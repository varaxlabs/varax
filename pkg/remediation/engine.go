package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/varax/operator/pkg/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// ProgressFunc is called after each action is processed.
type ProgressFunc func(completed, total int, action RemediationAction)

// Engine orchestrates remediation planning and execution.
type Engine struct {
	registry *RemediatorRegistry
	client   kubernetes.Interface
	dryRun   bool
}

// NewEngine creates a new remediation engine.
func NewEngine(registry *RemediatorRegistry, client kubernetes.Interface, dryRun bool) *Engine {
	return &Engine{registry: registry, client: client, dryRun: dryRun}
}

// PlanFromScanResult builds a remediation plan from failed check results.
func (e *Engine) PlanFromScanResult(ctx context.Context, scanResult *models.ScanResult) (*RemediationPlan, error) {
	plan := &RemediationPlan{
		ScanID: scanResult.ID,
		DryRun: e.dryRun,
	}

	for _, cr := range scanResult.Results {
		if cr.Status != models.StatusFail {
			continue
		}

		rem := e.registry.Get(cr.ID)
		if rem == nil {
			continue
		}

		// Filter out system namespace evidence
		var filtered []models.Evidence
		for _, ev := range cr.Evidence {
			if !isSystemNamespace(ev.Resource.Namespace) {
				filtered = append(filtered, ev)
			}
		}
		if len(filtered) == 0 {
			continue
		}

		actions, err := rem.Plan(ctx, e.client, filtered)
		if err != nil {
			continue
		}
		plan.Actions = append(plan.Actions, actions...)
	}

	return plan, nil
}

// Execute applies the actions in a plan and returns a report.
func (e *Engine) Execute(ctx context.Context, plan *RemediationPlan, progress ProgressFunc) (*RemediationReport, error) {
	start := time.Now()
	report := &RemediationReport{
		ID:        fmt.Sprintf("rem-%d", start.UnixMilli()),
		ScanID:    plan.ScanID,
		Timestamp: start.UTC(),
		DryRun:    plan.DryRun,
	}

	for i, action := range plan.Actions {
		result := RemediationResult{
			Action:    action,
			Timestamp: time.Now().UTC(),
		}

		// Skip system namespaces
		if isSystemNamespace(action.TargetNS) {
			result.Status = StatusSkipped
			result.SkipReason = SkipSystemNamespace
			report.Results = append(report.Results, result)
			if progress != nil {
				progress(i+1, len(plan.Actions), action)
			}
			continue
		}

		// Check exclusion label
		if hasExclusionLabel(ctx, e.client, action.TargetKind, action.TargetNS, action.TargetName) {
			result.Status = StatusSkipped
			result.SkipReason = SkipExclusionLabel
			report.Results = append(report.Results, result)
			if progress != nil {
				progress(i+1, len(plan.Actions), action)
			}
			continue
		}

		// Dispatch
		var err error
		switch action.ActionType {
		case ActionPatch:
			err = e.applyPatch(ctx, action, plan.DryRun)
		case ActionCreate:
			err = e.applyCreate(ctx, action, plan.DryRun)
		default:
			err = fmt.Errorf("unknown action type: %s", action.ActionType)
		}

		if err != nil {
			result.Status = StatusFailed
			result.Error = err.Error()
		} else if plan.DryRun {
			result.Status = StatusDryRun
		} else {
			result.Status = StatusApplied
			// Annotate for audit trail (best-effort)
			_ = annotateResource(ctx, e.client, action.TargetKind, action.TargetNS, action.TargetName)
		}

		report.Results = append(report.Results, result)
		if progress != nil {
			progress(i+1, len(plan.Actions), action)
		}
	}

	report.Duration = time.Since(start)
	report.Summary = summarizeResults(report.Results)
	return report, nil
}

func (e *Engine) applyPatch(ctx context.Context, action RemediationAction, dryRun bool) error {
	opts := metav1.PatchOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}

	patchType := types.StrategicMergePatchType

	switch action.TargetKind {
	case "Deployment":
		_, err := e.client.AppsV1().Deployments(action.TargetNS).Patch(ctx, action.TargetName, patchType, action.PatchJSON, opts)
		return err
	case "StatefulSet":
		_, err := e.client.AppsV1().StatefulSets(action.TargetNS).Patch(ctx, action.TargetName, patchType, action.PatchJSON, opts)
		return err
	case "DaemonSet":
		_, err := e.client.AppsV1().DaemonSets(action.TargetNS).Patch(ctx, action.TargetName, patchType, action.PatchJSON, opts)
		return err
	case "Pod":
		_, err := e.client.CoreV1().Pods(action.TargetNS).Patch(ctx, action.TargetName, patchType, action.PatchJSON, opts)
		return err
	case "ServiceAccount":
		_, err := e.client.CoreV1().ServiceAccounts(action.TargetNS).Patch(ctx, action.TargetName, patchType, action.PatchJSON, opts)
		return err
	default:
		return fmt.Errorf("unsupported patch target kind: %s", action.TargetKind)
	}
}

func (e *Engine) applyCreate(ctx context.Context, action RemediationAction, dryRun bool) error {
	opts := metav1.CreateOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}

	switch action.TargetKind {
	case "NetworkPolicy":
		return e.createNetworkPolicy(ctx, action, opts)
	case "LimitRange":
		return e.createLimitRange(ctx, action, opts)
	default:
		return fmt.Errorf("unsupported create target kind: %s", action.TargetKind)
	}
}

func (e *Engine) createNetworkPolicy(ctx context.Context, action RemediationAction, opts metav1.CreateOptions) error {
	var np networkingv1Policy
	if err := json.Unmarshal(action.PatchJSON, &np); err != nil {
		return fmt.Errorf("failed to unmarshal NetworkPolicy: %w", err)
	}

	// Use the K8s typed API
	netPol := np.toNetworkPolicy()
	_, err := e.client.NetworkingV1().NetworkPolicies(action.TargetNS).Create(ctx, netPol, opts)
	return err
}

func (e *Engine) createLimitRange(ctx context.Context, action RemediationAction, opts metav1.CreateOptions) error {
	var lr corev1LimitRange
	if err := json.Unmarshal(action.PatchJSON, &lr); err != nil {
		return fmt.Errorf("failed to unmarshal LimitRange: %w", err)
	}

	limitRange := lr.toLimitRange()
	_, err := e.client.CoreV1().LimitRanges(action.TargetNS).Create(ctx, limitRange, opts)
	return err
}

func summarizeResults(results []RemediationResult) RemediationSummary {
	s := RemediationSummary{TotalActions: len(results)}
	for _, r := range results {
		switch r.Status {
		case StatusApplied:
			s.AppliedCount++
		case StatusDryRun:
			s.DryRunCount++
		case StatusSkipped:
			s.SkippedCount++
		case StatusFailed:
			s.FailedCount++
		}
	}
	return s
}
