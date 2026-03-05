package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type EventRateLimitCheck struct{}

func (c *EventRateLimitCheck) ID() string          { return "CIS-1.2.9" }
func (c *EventRateLimitCheck) Name() string        { return "Ensure EventRateLimit admission is enabled" }
func (c *EventRateLimitCheck) Description() string { return "Verify EventRateLimit admission controller is enabled" }
func (c *EventRateLimitCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *EventRateLimitCheck) Benchmark() string         { return "CIS" }
func (c *EventRateLimitCheck) Section() string            { return "1.2.9" }

func (c *EventRateLimitCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--enable-admission-plugins")
		if ok && strings.Contains(val, "EventRateLimit") {
			return true, "EventRateLimit admission plugin is enabled"
		}
		return false, "EventRateLimit admission plugin is not enabled"
	})
}

var _ scanning.Check = &EventRateLimitCheck{}
