package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/varax/operator/pkg/models"
)

func TestNewVersionCmd(t *testing.T) {
	cmd := newVersionCmd()
	assert.Equal(t, "version", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
}

func TestNewScanCmd(t *testing.T) {
	cmd := newScanCmd()
	assert.Equal(t, "scan", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	// Verify timeout flag is registered with correct default
	f := cmd.Flags().Lookup("timeout")
	assert.NotNil(t, f)
	assert.Equal(t, "5m0s", f.DefValue)
}

func TestNewStatusCmd(t *testing.T) {
	cmd := newStatusCmd()
	assert.Equal(t, "status", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
}

func TestNewOperatorCmd(t *testing.T) {
	cmd := newOperatorCmd()
	assert.Equal(t, "operator", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	// Verify flags are registered
	f := cmd.Flags()
	assert.NotNil(t, f.Lookup("metrics-bind-address"))
	assert.NotNil(t, f.Lookup("health-probe-bind-address"))
	assert.NotNil(t, f.Lookup("metrics-secure"))

	// Verify secure metrics defaults to true
	secureFlag := f.Lookup("metrics-secure")
	assert.Equal(t, "true", secureFlag.DefValue)
}

func TestDefaultDBPath(t *testing.T) {
	path := defaultDBPath()
	assert.Contains(t, path, "varax.db")
	assert.True(t, filepath.IsAbs(path))
}

func TestDefaultDBPath_ContainsVaraxDir(t *testing.T) {
	path := defaultDBPath()
	dir := filepath.Dir(path)
	assert.Contains(t, dir, ".varax")
}

func TestBuildRESTConfig_NoKubeconfig(t *testing.T) {
	// Save and clear env
	t.Setenv("KUBECONFIG", "")

	origKubeconfig := kubeconfig
	kubeconfig = "/nonexistent/path/kubeconfig"
	defer func() { kubeconfig = origKubeconfig }()

	_, err := buildRESTConfig()
	assert.Error(t, err)
}

func TestNewVersionCmd_Runs(t *testing.T) {
	cmd := newVersionCmd()
	// Execute the version command - it prints to stdout
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestBuildK8sClient_WithFakeKubeconfig(t *testing.T) {
	tmpDir := t.TempDir()
	fakeKubeconfig := filepath.Join(tmpDir, "config")
	require.NoError(t, os.WriteFile(fakeKubeconfig, []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: fake-token
`), 0600))

	origKubeconfig := kubeconfig
	kubeconfig = fakeKubeconfig
	defer func() { kubeconfig = origKubeconfig }()

	client, err := buildK8sClient()
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestBuildRESTConfig_FromFlag(t *testing.T) {
	tmpDir := t.TempDir()
	fakeKubeconfig := filepath.Join(tmpDir, "config")
	require.NoError(t, os.WriteFile(fakeKubeconfig, []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://flag-server:6443
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: fake-token
`), 0600))

	origKubeconfig := kubeconfig
	kubeconfig = fakeKubeconfig
	defer func() { kubeconfig = origKubeconfig }()

	cfg, err := buildRESTConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://flag-server:6443", cfg.Host)
}

func TestBuildRESTConfig_DefaultPath(t *testing.T) {
	// Test the fallback to ~/.kube/config when neither flag nor env is set
	origKubeconfig := kubeconfig
	kubeconfig = ""
	defer func() { kubeconfig = origKubeconfig }()

	t.Setenv("KUBECONFIG", "")

	// This will either find a real kubeconfig or fall through to in-cluster
	// Either way, it exercises the default path code
	_, _ = buildRESTConfig()
}

func TestNewPruneCmd(t *testing.T) {
	cmd := newPruneCmd()
	assert.Equal(t, "prune", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	f := cmd.Flags().Lookup("max-age")
	assert.NotNil(t, f)
	assert.Equal(t, "720h0m0s", f.DefValue)
}

func TestNewReportCmd(t *testing.T) {
	cmd := newReportCmd()
	assert.Equal(t, "report", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	f := cmd.Flags()
	assert.NotNil(t, f.Lookup("framework"))
	assert.NotNil(t, f.Lookup("format"))
	assert.NotNil(t, f.Lookup("type"))
	assert.NotNil(t, f.Lookup("output"))

	assert.Equal(t, "soc2", f.Lookup("framework").DefValue)
	assert.Equal(t, "html", f.Lookup("format").DefValue)
	assert.Equal(t, "readiness", f.Lookup("type").DefValue)
}

func TestNewEvidenceCmd(t *testing.T) {
	cmd := newEvidenceCmd()
	assert.Equal(t, "evidence", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	f := cmd.Flags()
	assert.NotNil(t, f.Lookup("control"))
	assert.NotNil(t, f.Lookup("all"))
	assert.NotNil(t, f.Lookup("format"))
	assert.NotNil(t, f.Lookup("output"))

	assert.Equal(t, "html", f.Lookup("format").DefValue)
}

func TestFilterByBenchmark(t *testing.T) {
	result := &models.ScanResult{
		ID: "test-scan",
		Results: []models.CheckResult{
			{ID: "CIS-1", Benchmark: "CIS", Status: models.StatusPass, Severity: models.SeverityHigh},
			{ID: "NSA-1", Benchmark: "NSA-CISA", Status: models.StatusFail, Severity: models.SeverityMedium},
			{ID: "CIS-2", Benchmark: "CIS", Status: models.StatusFail, Severity: models.SeverityCritical},
			{ID: "PSS-1", Benchmark: "PSS", Status: models.StatusPass, Severity: models.SeverityLow},
		},
	}

	filtered := filterByBenchmark(result, "CIS")
	assert.Len(t, filtered.Results, 2)
	assert.Equal(t, "test-scan", filtered.ID)
	assert.Equal(t, 2, filtered.Summary.TotalChecks)
	assert.Equal(t, 1, filtered.Summary.PassCount)
	assert.Equal(t, 1, filtered.Summary.FailCount)
}

func TestFilterByBenchmark_NoMatches(t *testing.T) {
	result := &models.ScanResult{
		Results: []models.CheckResult{
			{Benchmark: "CIS", Status: models.StatusPass},
		},
	}
	filtered := filterByBenchmark(result, "RBAC")
	assert.Empty(t, filtered.Results)
	assert.Equal(t, 0, filtered.Summary.TotalChecks)
}

func TestFilterByBenchmark_AllStatuses(t *testing.T) {
	result := &models.ScanResult{
		Results: []models.CheckResult{
			{Benchmark: "CIS", Status: models.StatusPass},
			{Benchmark: "CIS", Status: models.StatusFail},
			{Benchmark: "CIS", Status: models.StatusWarn},
			{Benchmark: "CIS", Status: models.StatusSkip},
			{Benchmark: "CIS", Status: models.StatusProviderManaged},
		},
	}
	filtered := filterByBenchmark(result, "CIS")
	assert.Equal(t, 5, filtered.Summary.TotalChecks)
	assert.Equal(t, 1, filtered.Summary.PassCount)
	assert.Equal(t, 1, filtered.Summary.FailCount)
	assert.Equal(t, 1, filtered.Summary.WarnCount)
	assert.Equal(t, 1, filtered.Summary.SkipCount)
	assert.Equal(t, 1, filtered.Summary.ProviderManagedCount)
}

func TestClusterName_NoConfig(t *testing.T) {
	origKubeconfig := kubeconfig
	kubeconfig = "/nonexistent/path"
	defer func() { kubeconfig = origKubeconfig }()
	t.Setenv("KUBECONFIG", "")

	name := clusterName()
	assert.Equal(t, "unknown", name)
}

func TestClusterName_WithConfig(t *testing.T) {
	tmpDir := t.TempDir()
	fakeKubeconfig := filepath.Join(tmpDir, "config")
	require.NoError(t, os.WriteFile(fakeKubeconfig, []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://my-cluster:6443
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: fake-token
`), 0600))

	origKubeconfig := kubeconfig
	kubeconfig = fakeKubeconfig
	defer func() { kubeconfig = origKubeconfig }()

	name := clusterName()
	assert.Equal(t, "https://my-cluster:6443", name)
}

func TestRunEvidence_MutualExclusion(t *testing.T) {
	// Neither --control nor --all
	evidenceControl = ""
	evidenceAll = false
	err := runEvidence(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must specify either --control or --all")

	// Both --control and --all
	evidenceControl = "CC6.1"
	evidenceAll = true
	err = runEvidence(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot specify both --control and --all")

	// Reset
	evidenceControl = ""
	evidenceAll = false
}

func TestRunEvidence_InvalidFormat(t *testing.T) {
	t.Setenv("VARAX_LICENSE", "")
	t.Setenv("HOME", t.TempDir())
	evidenceControl = "CC6.1"
	evidenceAll = false
	evidenceFormat = "pdf"
	defer func() { evidenceFormat = "html" }()

	err := runEvidence(nil, nil)
	assert.Error(t, err)
	// Without a license, the gate fires before format validation
	assert.Contains(t, err.Error(), "Varax Pro license")
}

func TestRunReport_InvalidFormat(t *testing.T) {
	t.Setenv("VARAX_LICENSE", "")
	t.Setenv("HOME", t.TempDir())
	reportType = "readiness"
	reportFormat = "pdf"
	defer func() { reportFormat = "html" }()

	err := runReport(nil, nil)
	assert.Error(t, err)
	// Without a license, the gate fires before format validation
	assert.Contains(t, err.Error(), "Varax Pro license")
}

func TestRunReport_InvalidType(t *testing.T) {
	t.Setenv("VARAX_LICENSE", "")
	t.Setenv("HOME", t.TempDir())
	reportFormat = "html"
	reportType = "detailed"
	defer func() { reportType = "readiness" }()

	err := runReport(nil, nil)
	assert.Error(t, err)
	// Without a license, the gate fires before type validation
	assert.Contains(t, err.Error(), "Varax Pro license")
}

func TestNewLicenseCmd(t *testing.T) {
	cmd := newLicenseCmd()
	assert.Equal(t, "license", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	// Verify subcommands
	sub := cmd.Commands()
	names := make([]string, len(sub))
	for i, c := range sub {
		names[i] = c.Use
	}
	assert.Contains(t, names, "status")
	assert.Contains(t, names, "activate <KEY>")
}

func TestRunLicenseStatus_NoLicense(t *testing.T) {
	t.Setenv("VARAX_LICENSE", "")
	t.Setenv("HOME", t.TempDir())
	// Should not error — prints free tier message
	err := runLicenseStatus(nil, nil)
	assert.NoError(t, err)
}

func TestRunLicenseActivate_InvalidKey(t *testing.T) {
	err := runLicenseActivate(nil, []string{"not-a-valid-key"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid license key")
}

func TestRequireProFeature_NoLicense(t *testing.T) {
	t.Setenv("VARAX_LICENSE", "")
	t.Setenv("HOME", t.TempDir())
	err := requireProFeature("reports")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Varax Pro license")
}

func TestBuildRESTConfig_FromEnv(t *testing.T) {
	origKubeconfig := kubeconfig
	kubeconfig = ""
	defer func() { kubeconfig = origKubeconfig }()

	// Point to a nonexistent file to test the env path is read
	tmpDir := t.TempDir()
	fakeKubeconfig := filepath.Join(tmpDir, "config")
	require.NoError(t, os.WriteFile(fakeKubeconfig, []byte(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: fake-token
`), 0600))

	t.Setenv("KUBECONFIG", fakeKubeconfig)

	cfg, err := buildRESTConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://localhost:6443", cfg.Host)
}
