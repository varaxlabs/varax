package scanning

import (
	"context"
	"fmt"
	"time"

	"github.com/varax/operator/pkg/models"
	"k8s.io/client-go/kubernetes"
)

// ProgressCallback is called after each check completes.
type ProgressCallback func(completed, total int, current models.CheckResult)

// checkTimeout is the maximum duration for a single check execution.
const checkTimeout = 30 * time.Second

// ScanRunner orchestrates execution of compliance checks.
type ScanRunner struct {
	registry *Registry
	client   kubernetes.Interface
}

// NewScanRunner creates a ScanRunner with the given registry and Kubernetes client.
func NewScanRunner(registry *Registry, client kubernetes.Interface) *ScanRunner {
	return &ScanRunner{
		registry: registry,
		client:   client,
	}
}

// RunAll executes all registered checks and returns the aggregated result.
func (sr *ScanRunner) RunAll(ctx context.Context, progress ProgressCallback) (*models.ScanResult, error) {
	checks := sr.registry.All()
	if len(checks) == 0 {
		return nil, fmt.Errorf("no checks registered")
	}

	start := time.Now()

	// Pre-fetch all resources with pagination to avoid redundant API calls
	// and prevent OOM on large clusters. Failures are non-fatal.
	cache := BuildCache(ctx, sr.client)
	ctx = ContextWithCache(ctx, cache)

	results := make([]models.CheckResult, 0, len(checks))

	for i, check := range checks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var result models.CheckResult
		func() {
			defer func() {
				if r := recover(); r != nil {
					result = models.CheckResult{
						ID:       check.ID(),
						Name:     check.Name(),
						Severity: check.Severity(),
						Status:   models.StatusSkip,
						Message:  "check encountered an internal error",
					}
				}
			}()
			checkCtx, cancel := context.WithTimeout(ctx, checkTimeout)
			defer cancel()
			result = check.Run(checkCtx, sr.client)
		}()

		results = append(results, result)

		if progress != nil {
			progress(i+1, len(checks), result)
		}
	}

	duration := time.Since(start)
	summary := computeSummary(results)

	return &models.ScanResult{
		ID:        fmt.Sprintf("scan-%d", start.UnixMilli()),
		Timestamp: start,
		Duration:  duration,
		Results:   results,
		Summary:   summary,
	}, nil
}

func computeSummary(results []models.CheckResult) models.ScanSummary {
	var s models.ScanSummary
	s.TotalChecks = len(results)
	for _, r := range results {
		switch r.Status {
		case models.StatusPass:
			s.PassCount++
		case models.StatusFail:
			s.FailCount++
		case models.StatusWarn:
			s.WarnCount++
		case models.StatusSkip:
			s.SkipCount++
		case models.StatusProviderManaged:
			s.ProviderManagedCount++
		}
	}
	return s
}
