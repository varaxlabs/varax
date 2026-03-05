package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// Section 1.4 — Scheduler checks

type SchedulerProfilingCheck struct{}

func (c *SchedulerProfilingCheck) ID() string      { return "CIS-1.4.1" }
func (c *SchedulerProfilingCheck) Name() string    { return "Ensure scheduler profiling is disabled" }
func (c *SchedulerProfilingCheck) Description() string { return "Verify --profiling=false on kube-scheduler" }
func (c *SchedulerProfilingCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *SchedulerProfilingCheck) Benchmark() string         { return "CIS" }
func (c *SchedulerProfilingCheck) Section() string            { return "1.4.1" }

func (c *SchedulerProfilingCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-scheduler", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--profiling")
		if ok && val == "false" {
			return true, "Scheduler profiling is disabled"
		}
		return false, "Scheduler does not have --profiling=false"
	})
}

type SchedulerBindAddressCheck struct{}

func (c *SchedulerBindAddressCheck) ID() string      { return "CIS-1.4.2" }
func (c *SchedulerBindAddressCheck) Name() string    { return "Ensure scheduler bind address is 127.0.0.1" }
func (c *SchedulerBindAddressCheck) Description() string { return "Verify --bind-address=127.0.0.1 on kube-scheduler" }
func (c *SchedulerBindAddressCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *SchedulerBindAddressCheck) Benchmark() string         { return "CIS" }
func (c *SchedulerBindAddressCheck) Section() string            { return "1.4.2" }

func (c *SchedulerBindAddressCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-scheduler", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--bind-address")
		if !ok || val == "127.0.0.1" {
			return true, "Scheduler bind address is 127.0.0.1"
		}
		return false, "Scheduler --bind-address is not 127.0.0.1"
	})
}

var (
	_ scanning.Check = &SchedulerProfilingCheck{}
	_ scanning.Check = &SchedulerBindAddressCheck{}
)
