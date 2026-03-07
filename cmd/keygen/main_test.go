package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGenerateKeypairCmd(t *testing.T) {
	cmd := newGenerateKeypairCmd()
	assert.Equal(t, "generate-keypair", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
}

func TestNewSignCmd(t *testing.T) {
	cmd := newSignCmd()
	assert.Equal(t, "sign", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	f := cmd.Flags()
	assert.NotNil(t, f.Lookup("org"))
	assert.NotNil(t, f.Lookup("plan"))
	assert.NotNil(t, f.Lookup("features"))
	assert.NotNil(t, f.Lookup("duration"))
	assert.NotNil(t, f.Lookup("private-key"))
}

func TestRunSign_MissingPrivateKey(t *testing.T) {
	signPrivateKey = "/nonexistent/private.key"
	signOrg = "Test"
	defer func() { signPrivateKey = "private.key" }()

	err := runSign(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read private key")
}

func TestRunGenerateKeypair(t *testing.T) {
	// Run in temp dir to avoid polluting the repo
	origDir := t.TempDir()
	t.Chdir(origDir)

	err := runGenerateKeypair(nil, nil)
	assert.NoError(t, err)
}

func TestRunSign_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// Generate keypair
	err := runGenerateKeypair(nil, nil)
	require.NoError(t, err)

	signPrivateKey = "private.key"
	signOrg = "E2E Corp"
	signPlan = "pro-annual"
	signFeatures = "reports,evidence"
	signDuration = "30d"

	err = runSign(nil, nil)
	assert.NoError(t, err)
}

func TestRunSign_InvalidDuration(t *testing.T) {
	// Create a temp private key
	dir := t.TempDir()
	t.Chdir(dir)

	// Generate keypair first
	err := runGenerateKeypair(nil, nil)
	assert.NoError(t, err)

	signPrivateKey = "private.key"
	signOrg = "Test"
	signDuration = "abc"
	defer func() { signDuration = "365d" }()

	err = runSign(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid duration")
}
