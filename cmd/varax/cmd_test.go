package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
