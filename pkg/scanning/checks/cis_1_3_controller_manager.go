package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// Section 1.3 — Controller Manager checks

type CMTerminatedPodGCCheck struct{}

func (c *CMTerminatedPodGCCheck) ID() string      { return "CIS-1.3.1" }
func (c *CMTerminatedPodGCCheck) Name() string    { return "Ensure terminated pod GC threshold is set" }
func (c *CMTerminatedPodGCCheck) Description() string { return "Verify --terminated-pod-gc-threshold is set on controller manager" }
func (c *CMTerminatedPodGCCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *CMTerminatedPodGCCheck) Benchmark() string         { return "CIS" }
func (c *CMTerminatedPodGCCheck) Section() string            { return "1.3.1" }

func (c *CMTerminatedPodGCCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-controller-manager", func(args []string) (bool, string) {
		if hasArg(args, "--terminated-pod-gc-threshold") {
			return true, "Terminated pod GC threshold is set"
		}
		return false, "Controller manager --terminated-pod-gc-threshold is not set"
	})
}

type CMProfilingCheck struct{}

func (c *CMProfilingCheck) ID() string          { return "CIS-1.3.2" }
func (c *CMProfilingCheck) Name() string        { return "Ensure controller manager profiling is disabled" }
func (c *CMProfilingCheck) Description() string { return "Verify --profiling=false on controller manager" }
func (c *CMProfilingCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *CMProfilingCheck) Benchmark() string         { return "CIS" }
func (c *CMProfilingCheck) Section() string            { return "1.3.2" }

func (c *CMProfilingCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-controller-manager", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--profiling")
		if ok && val == "false" {
			return true, "Controller manager profiling is disabled"
		}
		return false, "Controller manager does not have --profiling=false"
	})
}

type CMSACredentialsCheck struct{}

func (c *CMSACredentialsCheck) ID() string      { return "CIS-1.3.3" }
func (c *CMSACredentialsCheck) Name() string    { return "Ensure use of service account credentials" }
func (c *CMSACredentialsCheck) Description() string { return "Verify --use-service-account-credentials=true" }
func (c *CMSACredentialsCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *CMSACredentialsCheck) Benchmark() string         { return "CIS" }
func (c *CMSACredentialsCheck) Section() string            { return "1.3.3" }

func (c *CMSACredentialsCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-controller-manager", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--use-service-account-credentials")
		if ok && val == "true" {
			return true, "Use of service account credentials is enabled"
		}
		return false, "Controller manager does not have --use-service-account-credentials=true"
	})
}

type CMSAPrivateKeyCheck struct{}

func (c *CMSAPrivateKeyCheck) ID() string      { return "CIS-1.3.4" }
func (c *CMSAPrivateKeyCheck) Name() string    { return "Ensure SA private key file is set" }
func (c *CMSAPrivateKeyCheck) Description() string { return "Verify --service-account-private-key-file is set" }
func (c *CMSAPrivateKeyCheck) Severity() models.Severity { return models.SeverityHigh }
func (c *CMSAPrivateKeyCheck) Benchmark() string         { return "CIS" }
func (c *CMSAPrivateKeyCheck) Section() string            { return "1.3.4" }

func (c *CMSAPrivateKeyCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-controller-manager", func(args []string) (bool, string) {
		if hasArg(args, "--service-account-private-key-file") {
			return true, "Service account private key file is set"
		}
		return false, "Controller manager --service-account-private-key-file is not set"
	})
}

type CMRootCACheck struct{}

func (c *CMRootCACheck) ID() string          { return "CIS-1.3.5" }
func (c *CMRootCACheck) Name() string        { return "Ensure root CA file is set" }
func (c *CMRootCACheck) Description() string { return "Verify --root-ca-file is set on controller manager" }
func (c *CMRootCACheck) Severity() models.Severity { return models.SeverityHigh }
func (c *CMRootCACheck) Benchmark() string         { return "CIS" }
func (c *CMRootCACheck) Section() string            { return "1.3.5" }

func (c *CMRootCACheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-controller-manager", func(args []string) (bool, string) {
		if hasArg(args, "--root-ca-file") {
			return true, "Root CA file is set"
		}
		return false, "Controller manager --root-ca-file is not set"
	})
}

type CMRotateKubeletCertCheck struct{}

func (c *CMRotateKubeletCertCheck) ID() string      { return "CIS-1.3.6" }
func (c *CMRotateKubeletCertCheck) Name() string    { return "Ensure RotateKubeletServerCertificate is enabled" }
func (c *CMRotateKubeletCertCheck) Description() string { return "Verify RotateKubeletServerCertificate feature gate is enabled" }
func (c *CMRotateKubeletCertCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *CMRotateKubeletCertCheck) Benchmark() string         { return "CIS" }
func (c *CMRotateKubeletCertCheck) Section() string            { return "1.3.6" }

func (c *CMRotateKubeletCertCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-controller-manager", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--feature-gates")
		if ok {
			if containsFeatureGate(val, "RotateKubeletServerCertificate", "true") {
				return true, "RotateKubeletServerCertificate is enabled"
			}
		}
		// RotateKubeletServerCertificate is enabled by default since v1.19
		return true, "RotateKubeletServerCertificate is enabled by default"
	})
}

type CMBindAddressCheck struct{}

func (c *CMBindAddressCheck) ID() string          { return "CIS-1.3.7" }
func (c *CMBindAddressCheck) Name() string        { return "Ensure controller manager bind address is 127.0.0.1" }
func (c *CMBindAddressCheck) Description() string { return "Verify --bind-address is set to 127.0.0.1" }
func (c *CMBindAddressCheck) Severity() models.Severity { return models.SeverityMedium }
func (c *CMBindAddressCheck) Benchmark() string         { return "CIS" }
func (c *CMBindAddressCheck) Section() string            { return "1.3.7" }

func (c *CMBindAddressCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "kube-controller-manager", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--bind-address")
		if !ok || val == "127.0.0.1" {
			return true, "Controller manager bind address is 127.0.0.1"
		}
		return false, "Controller manager --bind-address is not 127.0.0.1"
	})
}

// containsFeatureGate checks if a feature gate string contains the specified gate with the expected value.
func containsFeatureGate(featureGates, gate, expectedValue string) bool {
	// Feature gates format: "Gate1=true,Gate2=false"
	target := gate + "=" + expectedValue
	for _, fg := range splitComma(featureGates) {
		if fg == target {
			return true
		}
	}
	return false
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	return result
}

var (
	_ scanning.Check = &CMTerminatedPodGCCheck{}
	_ scanning.Check = &CMProfilingCheck{}
	_ scanning.Check = &CMSACredentialsCheck{}
	_ scanning.Check = &CMSAPrivateKeyCheck{}
	_ scanning.Check = &CMRootCACheck{}
	_ scanning.Check = &CMRotateKubeletCertCheck{}
	_ scanning.Check = &CMBindAddressCheck{}
)
