package checks

import (
	"context"

	"github.com/varax/operator/pkg/models"
	"github.com/varax/operator/pkg/scanning"
	"k8s.io/client-go/kubernetes"
)

// Section 2 — etcd checks

type EtcdCertFileCheck struct{}

func (c *EtcdCertFileCheck) ID() string      { return "CIS-2.1" }
func (c *EtcdCertFileCheck) Name() string    { return "Ensure etcd cert-file and key-file are set" }
func (c *EtcdCertFileCheck) Description() string { return "Verify --cert-file and --key-file are set on etcd" }
func (c *EtcdCertFileCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *EtcdCertFileCheck) Benchmark() string         { return "CIS" }
func (c *EtcdCertFileCheck) Section() string            { return "2.1" }

func (c *EtcdCertFileCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "etcd", func(args []string) (bool, string) {
		hasCert := hasArg(args, "--cert-file")
		hasKey := hasArg(args, "--key-file")
		if hasCert && hasKey {
			return true, "etcd cert-file and key-file are set"
		}
		return false, "etcd missing --cert-file and/or --key-file"
	})
}

type EtcdClientCertAuthCheck struct{}

func (c *EtcdClientCertAuthCheck) ID() string      { return "CIS-2.2" }
func (c *EtcdClientCertAuthCheck) Name() string    { return "Ensure etcd client cert auth is enabled" }
func (c *EtcdClientCertAuthCheck) Description() string { return "Verify --client-cert-auth=true on etcd" }
func (c *EtcdClientCertAuthCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *EtcdClientCertAuthCheck) Benchmark() string         { return "CIS" }
func (c *EtcdClientCertAuthCheck) Section() string            { return "2.2" }

func (c *EtcdClientCertAuthCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "etcd", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--client-cert-auth")
		if ok && val == "true" {
			return true, "etcd client cert auth is enabled"
		}
		return false, "etcd does not have --client-cert-auth=true"
	})
}

type EtcdAutoTLSCheck struct{}

func (c *EtcdAutoTLSCheck) ID() string          { return "CIS-2.3" }
func (c *EtcdAutoTLSCheck) Name() string        { return "Ensure etcd auto-tls is not enabled" }
func (c *EtcdAutoTLSCheck) Description() string { return "Verify --auto-tls is not set to true" }
func (c *EtcdAutoTLSCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *EtcdAutoTLSCheck) Benchmark() string         { return "CIS" }
func (c *EtcdAutoTLSCheck) Section() string            { return "2.3" }

func (c *EtcdAutoTLSCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "etcd", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--auto-tls")
		if ok && val == "true" {
			return false, "etcd has --auto-tls=true (insecure)"
		}
		return true, "etcd auto-tls is not enabled"
	})
}

type EtcdPeerCertCheck struct{}

func (c *EtcdPeerCertCheck) ID() string      { return "CIS-2.4" }
func (c *EtcdPeerCertCheck) Name() string    { return "Ensure etcd peer cert-file and key-file are set" }
func (c *EtcdPeerCertCheck) Description() string { return "Verify --peer-cert-file and --peer-key-file are set" }
func (c *EtcdPeerCertCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *EtcdPeerCertCheck) Benchmark() string         { return "CIS" }
func (c *EtcdPeerCertCheck) Section() string            { return "2.4" }

func (c *EtcdPeerCertCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "etcd", func(args []string) (bool, string) {
		hasCert := hasArg(args, "--peer-cert-file")
		hasKey := hasArg(args, "--peer-key-file")
		if hasCert && hasKey {
			return true, "etcd peer cert-file and key-file are set"
		}
		return false, "etcd missing --peer-cert-file and/or --peer-key-file"
	})
}

type EtcdPeerClientCertAuthCheck struct{}

func (c *EtcdPeerClientCertAuthCheck) ID() string      { return "CIS-2.5" }
func (c *EtcdPeerClientCertAuthCheck) Name() string    { return "Ensure etcd peer client cert auth is enabled" }
func (c *EtcdPeerClientCertAuthCheck) Description() string { return "Verify --peer-client-cert-auth=true on etcd" }
func (c *EtcdPeerClientCertAuthCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *EtcdPeerClientCertAuthCheck) Benchmark() string         { return "CIS" }
func (c *EtcdPeerClientCertAuthCheck) Section() string            { return "2.5" }

func (c *EtcdPeerClientCertAuthCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "etcd", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--peer-client-cert-auth")
		if ok && val == "true" {
			return true, "etcd peer client cert auth is enabled"
		}
		return false, "etcd does not have --peer-client-cert-auth=true"
	})
}

type EtcdPeerAutoTLSCheck struct{}

func (c *EtcdPeerAutoTLSCheck) ID() string          { return "CIS-2.6" }
func (c *EtcdPeerAutoTLSCheck) Name() string        { return "Ensure etcd peer auto-tls is not enabled" }
func (c *EtcdPeerAutoTLSCheck) Description() string { return "Verify --peer-auto-tls is not set to true" }
func (c *EtcdPeerAutoTLSCheck) Severity() models.Severity { return models.SeverityCritical }
func (c *EtcdPeerAutoTLSCheck) Benchmark() string         { return "CIS" }
func (c *EtcdPeerAutoTLSCheck) Section() string            { return "2.6" }

func (c *EtcdPeerAutoTLSCheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "etcd", func(args []string) (bool, string) {
		val, ok := getArgValue(args, "--peer-auto-tls")
		if ok && val == "true" {
			return false, "etcd has --peer-auto-tls=true (insecure)"
		}
		return true, "etcd peer auto-tls is not enabled"
	})
}

type EtcdUniqueCACheck struct{}

func (c *EtcdUniqueCACheck) ID() string          { return "CIS-2.7" }
func (c *EtcdUniqueCACheck) Name() string        { return "Ensure unique CA for etcd" }
func (c *EtcdUniqueCACheck) Description() string { return "Verify --trusted-ca-file is set for etcd" }
func (c *EtcdUniqueCACheck) Severity() models.Severity { return models.SeverityCritical }
func (c *EtcdUniqueCACheck) Benchmark() string         { return "CIS" }
func (c *EtcdUniqueCACheck) Section() string            { return "2.7" }

func (c *EtcdUniqueCACheck) Run(ctx context.Context, client kubernetes.Interface) models.CheckResult {
	return runControlPlaneArgCheck(ctx, client, c, "etcd", func(args []string) (bool, string) {
		if hasArg(args, "--trusted-ca-file") {
			return true, "etcd trusted CA file is set"
		}
		return false, "etcd --trusted-ca-file is not set"
	})
}

var (
	_ scanning.Check = &EtcdCertFileCheck{}
	_ scanning.Check = &EtcdClientCertAuthCheck{}
	_ scanning.Check = &EtcdAutoTLSCheck{}
	_ scanning.Check = &EtcdPeerCertCheck{}
	_ scanning.Check = &EtcdPeerClientCertAuthCheck{}
	_ scanning.Check = &EtcdPeerAutoTLSCheck{}
	_ scanning.Check = &EtcdUniqueCACheck{}
)
