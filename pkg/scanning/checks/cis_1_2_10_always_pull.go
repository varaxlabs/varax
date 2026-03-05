package checks

import (
	"context"
	"strings"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

type AlwaysPullImagesCheck struct{}

func (c *AlwaysPullImagesCheck) ID() string          { return "CIS-1.2.10" }
func (c *AlwaysPullImagesCheck) Name() string        { return "Ensure AlwaysPullImages admission is enabled" }
func (c *AlwaysPullImagesCheck) Description() string { return "Verify AlwaysPullImages admission controller is enabled" }
func (c *AlwaysPullImagesCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *AlwaysPullImagesCheck) Benchmark() string         { return "CIS" }
func (c *AlwaysPullImagesCheck) Section() string            { return "1.2.10" }

func (c *AlwaysPullImagesCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-apiserver", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--enable-admission-plugins")
		if ok && strings.Contains(val, "AlwaysPullImages") {
			return true, "AlwaysPullImages admission plugin is enabled"
		}
		return false, "AlwaysPullImages admission plugin is not enabled"
	})
}

var _ scanning.Check = &AlwaysPullImagesCheck{}
